// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2016-2020 by Marc Schink <dev@zapb.de>
 * Copyright (C) 2023 by Cadence Design Systems, Inc.
 *
 * Based on RTT server.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <helper/log.h>
#include <helper/list.h>
#include <server/server.h>
#include <target/target.h>
#include <target/trax.h>

#include "trax.h"
#include "tpack.h"


#define TRAX_TARGETS_PER_DEV	1
#define RETRY_MAX				100
#define	MEMACCESS_BUFLEN		(1024 * 1024)	// Buffer for incoming memory access commands

struct trax {
	bool valid;
	struct trax_source source;
	/** Control block. */
	struct trax_control ctrl;
	struct target *target;
	/** Whether a TRAX device was found. */
	bool found;
	/** Whether TRAX device is Xtensa flavor. */
	bool is_xtensa;

	/** For TPACK channel management (excluding socket support) */
	tpack_socket *tsock;

	struct trax_sink_list **sink_list;
	size_t sink_list_length;

	uint8_t *memaccess_buf;

	uint32_t start_addr;
	uint32_t end_addr;
	uint32_t ram_size;
};

struct trax *trax;
unsigned int ntrax;


// Local declarations
static tpack_socket *trax_tsock_create(unsigned int trid);
static void trax_tsock_release(struct trax *ptrax);
static int trax_tpack_gchan_rx_packet(tpack_channel *gchan, void *arg,
				int pieceno, tpack_header *packet, int len);
static int trax_tpack_tchan_rx_packet(tpack_channel *tchan, void *arg,
				int pieceno, tpack_header *packet, int len);
static int trax_readmem(struct trax *ptrax, uint8_t *data, uint32_t addr, uint32_t count);
static int trax_writemem(struct trax *ptrax, uint8_t *data, uint32_t addr, uint32_t count);


static struct trax *trax_get_ptr(unsigned int chid)
{
	if (chid >= ntrax || !trax)
		return NULL;
	return &trax[chid];
}

static int trax_alloc(unsigned int trid)
{
	struct trax *ptrax;
	if (trid >= ntrax) {
		unsigned int newlen = trid + 1;
		struct trax *tmp = realloc(trax, sizeof(struct trax) * newlen);
		if (!tmp)
			return ERROR_FAIL;
		for (size_t i = ntrax; i < newlen; i++)
			tmp[i].valid = false;
		trax = tmp;
		ntrax = newlen;
	}

	ptrax = &trax[trid];
	memset(ptrax, 0, sizeof(struct trax));
	ptrax->sink_list_length = 1;
	ptrax->sink_list = calloc(ptrax->sink_list_length, sizeof(struct trax_sink_list *));
	ptrax->memaccess_buf = calloc(MEMACCESS_BUFLEN, 1);

	if (!ptrax->sink_list || !ptrax->memaccess_buf) {
		free(ptrax->sink_list);
		free(ptrax->memaccess_buf);
		ptrax->valid = false;
		return ERROR_FAIL;
	}

	ptrax->valid = true;
	return ERROR_OK;
}

static int trax_free(unsigned int trid)
{
	struct trax *ptrax = trax_get_ptr(trid);
	if (!ptrax)
		return ERROR_FAIL;
	if (ptrax->valid) {
		ptrax->target = NULL;
		free(ptrax->sink_list);
		free(ptrax->memaccess_buf);
	    trax_tsock_release(ptrax);
		ptrax->valid = false;
	}
	return ERROR_OK;
}

int trax_init(void)
{
	trax = NULL;
	ntrax = 0;
	return 0;
}

int trax_exit(void)
{
	int ret = ERROR_OK;
	for (unsigned int i = 0; i < ntrax; i++)
		if (trax[i].valid)
			ret = trax_free(i);
	free(trax);
	trax = NULL;
	ntrax = 0;
	return ret;
}

static int trax_register_source(unsigned int trid, const struct trax_source source)
{
	struct trax *ptrax = trax_get_ptr(trid);
	if (!ptrax)
		return ERROR_FAIL;
	if (!source.attach || !source.write ||
		!source.start || !source.stop ||
		!source.dm_readreg || !source.dm_writereg)
		return ERROR_FAIL;
	ptrax->source.attach = source.attach;
	ptrax->source.start = source.start;
	ptrax->source.stop = source.stop;
	ptrax->source.write = source.write;
	ptrax->source.dm_readreg = source.dm_readreg;
	ptrax->source.dm_writereg = source.dm_writereg;
	return ERROR_OK;
}

int trax_start(unsigned int trid, struct target *target, const struct trax_source source)
{
	struct trax *ptrax;
	if (trax_alloc(trid) || trax_register_source(trid, source)) {
		trax_free(trid);
		return ERROR_FAIL;
	}

	ptrax = &trax[trid];
	ptrax->source.attach(target, &ptrax->found, &ptrax->is_xtensa);
	if (!ptrax->found) {
		LOG_ERROR("trax: Attach did not find any TRAX targets");
		return ERROR_OK;	// allow openocd to continue running
	}

	int ret = ptrax->source.start(target, NULL);
	if (ret != ERROR_OK)
		return ret;

	LOG_INFO("trax: Attach found TRAX target");
	ptrax->ctrl.num_up_channels++;
	ptrax->ctrl.num_down_channels++;
	ptrax->target = target;
	return ERROR_OK;
}

int trax_stop(unsigned int trid)
{
	struct trax *ptrax = trax_get_ptr(trid);
	if (!ptrax)
		return ERROR_FAIL;
	if (!ptrax->valid)
		return ERROR_FAIL;
	if (!ptrax->ctrl.num_up_channels || !ptrax->ctrl.num_down_channels) {
		LOG_ERROR("trax: No channels configured");
		return ERROR_FAIL;
	}

	ptrax->ctrl.num_up_channels--;
	ptrax->ctrl.num_down_channels--;
	if (!ptrax->ctrl.num_up_channels || !ptrax->ctrl.num_down_channels)
		return trax_free(trid);
	return ERROR_OK;
}

static int adjust_sink_list(struct trax *ptrax, size_t length)
{
	struct trax_sink_list **tmp;

	if (length <= ptrax->sink_list_length)
		return ERROR_OK;

	tmp = realloc(ptrax->sink_list, sizeof(struct trax_sink_list *) * length);
	if (!tmp)
		return ERROR_FAIL;

	for (size_t i = ptrax->sink_list_length; i < length; i++)
		tmp[i] = NULL;
	ptrax->sink_list = tmp;
	ptrax->sink_list_length = length;
	return ERROR_OK;
}

// NOTE: Currently only one sink per TRAX/TCP channel is supported.
// Multiple TRAX/TCP channels are supported, but each with only one sink.
// TPACK muxes multiple virtual channels over each TRAX/TCP channel.
//
// TODO: The sink list could be removed once we're sure we don't
// eventually plan to allow multiple sinks per TRAX/TCP channel...
int trax_register_sink(unsigned int chid, void *user_data)
{
	struct trax_sink_list *tmp;
	struct trax *ptrax = trax_get_ptr(chid);
	if (!ptrax)
		return ERROR_FAIL;

	if (chid >= ntrax || !ptrax || !ptrax->valid)
		return ERROR_FAIL;
	if (chid < ptrax->sink_list_length && ptrax->sink_list[chid]) {
		LOG_ERROR("trax: Already registered sink for channel %u", chid);
		return ERROR_FAIL;
	}
	if (chid >= ptrax->sink_list_length) {
		if (adjust_sink_list(ptrax, chid + 1) != ERROR_OK)
			return ERROR_FAIL;
	}

	LOG_DEBUG("trax: Registering sink for channel %u", chid);

	tmp = malloc(sizeof(struct trax_sink_list));

	if (!tmp)
		return ERROR_FAIL;

	tmp->user_data = user_data;
	tmp->next = ptrax->sink_list[chid];
	ptrax->sink_list[chid] = tmp;
	return ERROR_OK;
}

int trax_unregister_sink(unsigned int chid, void *user_data)
{
	struct trax_sink_list *prev_sink;
	struct trax *ptrax = trax_get_ptr(chid);
	if (!ptrax)
		return ERROR_FAIL;

	if (!ptrax->valid || chid >= ptrax->sink_list_length)
		return ERROR_FAIL;

	LOG_DEBUG("trax: Unregistering sink for channel %u", chid);
	prev_sink = ptrax->sink_list[chid];
	for (struct trax_sink_list *sink = ptrax->sink_list[chid]; sink;
			prev_sink = sink, sink = sink->next) {
		if (sink->user_data == user_data) {
			if (sink == ptrax->sink_list[chid])
				ptrax->sink_list[chid] = sink->next;
			else
				prev_sink->next = sink->next;
			free(sink);
			if (!ptrax->sink_list[chid])
				trax_tsock_release(ptrax);
			return ERROR_OK;
		}
	}

	return ERROR_OK;
}

// Implement TPACK send_bytes() call here since we need the sink connection
int send_bytes(tpack_socket *tsock, unsigned char *buffer, int length)
{
	unsigned int trid = (tsock && tsock->gchannel && tsock->gchannel->rx_packet_arg) ?
		*(unsigned int *)tsock->gchannel->rx_packet_arg : 0;
	struct connection *connection = (struct connection *)(trax[trid].sink_list[trid]->user_data);
	int ret = connection_write(connection, buffer, length);
	if (ret < 0) {
		LOG_ERROR("Failed to write data to socket.");
		if (tsock)
			tsock->tx_done = -1;
	} else if (ret > 0) {
		ret = 0;	// TPACK expects a success/fail return
	}
	return ret;
}

// Special handling of first packet on a new connection
// Allocate and initialize TPACK-related structures
static tpack_socket *trax_tsock_create(unsigned int trid)
{
	tpack_socket *tsock = calloc(1, sizeof(tpack_socket));
	if (!tsock) {
		LOG_ERROR("trax tsock: out of memory");
		return NULL;
	}
	// Initialization similar to contents of tpack_sock_startup()
	tsock->alloc_chans = TPACK_DEFAULT_ALLOC_CHANNELS;
	tsock->channels = tsock->dchannels;
	tsock->trid = trid;
	tsock->gchannel = tpack_channel_alloc(tsock,
		trax_tpack_gchan_rx_packet, (void *)&tsock->trid, 0, sizeof(tpack_channel), 0);
	if (!tsock->gchannel) {
		LOG_ERROR("trax gchan: out of memory");
		free(tsock);
		return NULL;
	}
	tsock->gchannel->tsock = tsock;
	return tsock;
}

static void trax_tsock_release(struct trax *ptrax)
{
	tpack_socket *tsock = ptrax->tsock;
	if (tsock) {
		tpack_channel_release(tsock->gchannel);
		if (tsock->channels != tsock->dchannels)	/* can't free dchannels[] */
			free(tsock->channels);
		free(tsock);
		ptrax->tsock = NULL;
	}
}

static int trax_handle_init_packet(unsigned int trid, tpack_init_packet *init_pkt)
{
	tpack_init_packet send_pkt;
	tpack_apinfo *apinfo;
	int retval = ERROR_OK, rcode;
	struct trax *ptrax = trax_get_ptr(trid);
	if (!ptrax) {
		LOG_ERROR("trax: invalid trid %d or NULL instance", trid);
		return 0;
	}

	// Create structures for new connection
	if (!ptrax->tsock) {
		ptrax->tsock = trax_tsock_create(trid);
		if (!ptrax->tsock)
			return ERROR_FAIL;	// tsock not allocated so cannot send packet response
	}

	// Send handshake packet with STARTUP rcode
	// NOTE: send occurs prior to receive packet processing
	rcode = TPACK_CMD_STARTUP;
	memset(&send_pkt, 0, sizeof(tpack_init_packet));
	send_pkt.min_version = TPACK_VERSION;
	send_pkt.max_version = TPACK_VERSION;
	if (tpack_send(ptrax->tsock->gchannel, &apinfo, 0,
			&send_pkt.h, sizeof(tpack_init_packet), 0, 0, rcode, 0, 0, 0, 0)) {
		LOG_ERROR("trax: failed to send handshake packet");
		return ERROR_FAIL;
	}

	// Receive and process handshake packet
	tpack_receive_process_header(ptrax->tsock, &init_pkt->h, &apinfo);
	if (init_pkt->h.rcode != TPACK_CMD_STARTUP ||
		init_pkt->min_version > TPACK_VERSION || init_pkt->max_version < TPACK_VERSION) {
		LOG_ERROR("trax: invalid/incompatible init packet");
		retval = ERROR_FAIL;
	}
	LOG_DEBUG("trax: processed STARTUP handshake");
	return retval;
}

static int trax_handle_recv_packet(struct trax *ptrax, tpack_header *packet, size_t dispatch_len)
{
	tpack_channel *tchan = NULL;
	tpack_apinfo *apinfo = NULL;
	tpack_rx_fn *rx_func = NULL;
	void *rx_arg = NULL;
	int rc;

	tchan = tpack_receive_process_header(ptrax->tsock, packet, &apinfo);
	if (!tchan) {
		LOG_ERROR("trax: receive processing resulted in invalid channel");
		return ERROR_FAIL;
	}
	if (apinfo != 0) {
		rx_func = apinfo->rx_func;
		rx_arg  = apinfo->rx_arg;
	}
	// TODO: How many bytes do we dispatch?
	if (apinfo != 0) {
		tpack_active_release(tchan, apinfo);        /* done with this rx packet */
		ptrax->tsock->rx_apinfo = 0;                /* (just to be sure) */
	}
	// TODO: handle partial packets using rc = ptrax->tsock->rx_piece_no++;
	rc = 0;
	tpack_print_packet(ptrax->tsock, tchan, "recv", apinfo, packet, dispatch_len, 0, 0, 0);
	if (tchan != 0)									/* if packet not being dropped */
		tpack_process_receive_packet(ptrax->tsock, tchan, rc, packet, dispatch_len, rx_func, rx_arg);
	// Above might close channel, etc, so do nothing afterwards (here).

	// TODO: ensure EAGAIN / EINTR / socket errors are handled gracefully
	return ERROR_OK;
}

int trax_write_channel(unsigned int channel_index, const uint8_t *buffer, size_t *length)
{
	struct trax *ptrax = trax_get_ptr(channel_index);
	if (!ptrax) {
		LOG_ERROR("trax: invalid trid %d or NULL instance", channel_index);
		return 0;
	}
	if (!ptrax->ctrl.num_up_channels || !ptrax->ctrl.num_down_channels) {
		LOG_ERROR("trax: Down-channel %u is not available", channel_index);
		return ERROR_FAIL;
	}

	if (!length || (*length < sizeof(tpack_header))) {
		// TODO: keep data and concatenate partial packets?
		LOG_ERROR("trax: unexpected RX packet length %lu", length ? *length : 0);
		return ERROR_FAIL;
	}

	if (!ptrax->tsock)
		return trax_handle_init_packet(channel_index, (tpack_init_packet *)buffer);

	// Run packet through TPACK processing logic (similar to tpack_process_receive())
	int retval = trax_handle_recv_packet(ptrax, (tpack_header *)buffer, *length);
	return retval;
}

static int trax_tpack_gchan_rx_packet(tpack_channel *gchan, void *arg,
				int pieceno, tpack_header *packet, int len)
{
	tpack_socket *tsock = gchan->tsock;
	trax_packet reply;
	unsigned int trid = arg ? *(unsigned int *)arg : 0;
	struct trax *ptrax = trax_get_ptr(trid);
	if (!ptrax) {
		LOG_ERROR("trax: invalid trid %d or NULL instance", trid);
		return 0;
	}

	tpack_print_packet(tsock, gchan, "info: packet:", 0, packet, len, 0, 0, 0);

	if (pieceno < 0) {            /* error, channel closed before complete response received */
		tpack_channel_close(gchan, 0, 0, 0);        /* acknowledge channel closure */
		/* FIXME: gchannel should never close -- so close the whole socket instead? */
		return 0;
	}
	if (pieceno > 0)              /* just ignore/drop extra packet payloads */
		return 0;
	/*  Start of packet arrived...  */

	/*  Check odd packet sequences.  */
	if ((packet->flags & TPACK_HF_FIRST) == 0) {
		tpack_print_packet(tsock, gchan, "unexpected packet, untracked mid-transaction, dropped",
			0, packet, len, 0, 0, 0);       /* drop -- and error too!? FIXME */
		return 0;
	}
	if ((packet->flags & TPACK_HF_MORE) == 0) {
		tpack_print_packet(tsock, gchan, "unexpected request not expecting reply, dropped",
			0, packet, len, 0, 0, 0);       /* drop */
		return 0;
	}

	/*  If it's a normal request packet...  */
	switch (packet->rcode) {
	case TPACK_CMD_LIST:
	{
		reply.data[0] = htonl(TRAX_TARGETS_PER_DEV);
		tpack_send(gchan, 0, packet, &reply.h, sizeof(tpack_header) + 4, 0, 0, 0, 0, 0, 0, 0);
		break;
	}

	case TPACK_CMD_OPEN:
	{
		tpack_open_packet *opacket = (tpack_open_packet *)packet;
		tpack_u16 major = ntohs(opacket->dest_major);
		tpack_u16 minor = ntohs(opacket->dest_minor);

		/*  What is being opened?  */
		if (major == TPACK_MAJOR_TRAX) {
			/*  A TRAX unit!  What a surprise.  Which one?  */
			if (minor >= TRAX_TARGETS_PER_DEV) {
				/*  Invalid TRAX unit (device) number, out of range.  */
				LOG_DEBUG("open request for out-of-range TRAX device number %d (only have %d units)",
					minor, TRAX_TARGETS_PER_DEV);
				tpack_send(gchan, 0, packet, &reply.h, 0, 0, 0, ERROR_FAIL, 0, 0, 0, 0);
				break;
			}
			/* TODO FIXME: check for exclusive use of a device!?!? */
			/* TODO FIXME: track number of open channels to each device? */
			/*
			 * NOTE TODO: An alternative is to treat channel as a bitset of targets,
			 * thus making possible broadcast messages.
			 */

			tpack_channel *tchan;
			if (tpack_channel_open_accept(gchan, packet, &tchan,
					trax_tpack_tchan_rx_packet, arg, 1024, sizeof(tpack_channel), 0))
				break;
		} else if (major == TPACK_MAJOR_GENERIC) {
			tpack_print_packet(tsock, gchan, "generic open requests not supported",
								0, packet, len, 0, 0, 0);
			tpack_send(gchan, 0, packet, &reply.h, 0, 0, 0, ERROR_FAIL, 0, 0, 0, 0);
		} else {
			tpack_print_packet(tsock, gchan, "unrecognized open request",
								0, packet, len, 0, 0, 0);
			tpack_send(gchan, 0, packet, &reply.h, 0, 0, 0, ERROR_FAIL, 0, 0, 0, 0);
		}
		break;
	}

	default:
	{
		tpack_print_packet(tsock, gchan, "unrecognized request on control channel",
						0, packet, len, 0, 0, 0);
		tpack_send(gchan, 0, packet, &reply.h, 0, 0, 0, ERROR_FAIL, 0, 0, 0, 0);
		break;
	}
	}

	return 0;
}

static int trax_tpack_tchan_rx_packet(tpack_channel *tchan, void *arg,
				int pieceno, tpack_header *packet, int len)
{
	unsigned int trid = arg ? *(unsigned int *)arg : 0;
	tpack_socket *tsock = tchan->tsock;
	trax_packet *tpacket = (trax_packet *)packet;
	trax_packet reply;
	uint32_t regno, value;
	uint32_t addr, count;
	int rc = ERROR_OK;
	struct trax *ptrax = trax_get_ptr(trid);
	if (!ptrax) {
		LOG_ERROR("trax: invalid trid %d or NULL instance", trid);
		return 0;
	}

	LOG_DEBUG("trax TPACK tchan rx_packet: tchan %p arg %p pieceno %d packet %p len %d",
		tchan, arg, pieceno, packet, len);

	tpack_print_packet(tsock, tchan, "info: packet:", 0, packet, len, 0, 0, 0);

	if (pieceno < 0) {            /* error, channel closed before complete response received */
		tpack_channel_close(tchan, 0, 0, 0);        /* acknowledge channel closure */
		return 0;
	}
	if (pieceno > 0)              /* just ignore/drop extra packet payloads */
		return 0;
	/*  Start of packet arrived...  */

	/*  Check odd packet sequences.  */
	if ((packet->flags & TPACK_HF_FIRST) == 0) {
		tpack_print_packet(tsock, tchan, "unexpected packet, untracked mid-transaction, dropped",
			0, packet, len, 0, 0, 0);       /* drop -- and error too!? FIXME */
		return 0;
	}
	if ((packet->flags & TPACK_HF_MORE) == 0) {
		tpack_print_packet(tsock, tchan, "unexpected request not expecting reply, dropped",
			0, packet, len, 0, 0, 0);       /* drop */
		return 0;
	}

	/*  If it's a normal request packet...  */
	switch (packet->rcode) {
	case TPACK_CMD_READREG:
	{
		regno = ntohl(tpacket->data[0]);

		if (packet->length < sizeof(tpack_header) + 4) {
			LOG_ERROR("TRAX: readreg packet too small (%d bytes)", packet->length);
			break;
		}
		if ((regno & TRAX_REG_MASK) == TRAX_PSEUDOREG1_RW) {
			LOG_DEBUG("TRAX: Ignoring pseudo-reg read to 0x%x", regno);
			break;
		}
		rc = ptrax->source.dm_readreg(ptrax->target, regno, &value);
		LOG_DEBUG("TRAX: ReadReg: 0x%x = %x (%d)", regno, value, rc);
		reply.data[0] = htonl(value);
		rc = tpack_send(tchan, 0, packet, &reply.h, sizeof(tpack_header) + 4, 0, 0, rc, 0, 0, 0, 0);
		if (rc != ERROR_OK)
			LOG_ERROR("TRAX: TPACK_CMD_READREG: Sending packet returned error %d", rc);
		return rc;
	}

	case TPACK_CMD_WRITEREG:
	{
		regno = ntohl(tpacket->data[0]);
		value = ntohl(tpacket->data[1]);

		if (packet->length < sizeof(tpack_header) + 8) {
			LOG_ERROR("TRAX: writereg packet too small (%d bytes)", packet->length);
			rc = ERROR_FAIL;
			break;
		}
		if (((regno & TRAX_REG_MASK) == TRAX_PSEUDOREG0_W) ||
			((regno & TRAX_REG_MASK) == TRAX_PSEUDOREG1_RW)) {
			LOG_DEBUG("TRAX: Ignoring pseudo-reg write to 0x%x", regno);
			break;
		}
		if (regno & 3) {
			LOG_ERROR("TRAX: skipping invalid write to register 0x%x", regno);
			break;
		}
		rc = ptrax->source.dm_writereg(ptrax->target, regno, value);
		LOG_DEBUG("TRAX: WriteReg: 0x%x -> %x (%d)", regno, value, rc);
		break;
	}

	case TPACK_CMD_READMEM:
	{
		addr = ntohl(tpacket->data[0]);
		count = ntohl(tpacket->data[1]);
		uint8_t *data = ptrax->memaccess_buf;

		if (packet->length < sizeof(tpack_header) + 8) {
			LOG_ERROR("TRAX: readmem packet too small (%d bytes)", packet->length);
			rc = ERROR_FAIL;
			break;
		}
		if (count > MEMACCESS_BUFLEN) {
			LOG_ERROR("TRAX: readmem request too large (%d bytes, can handle %d bytes)", count, MEMACCESS_BUFLEN);
			rc = ERROR_FAIL;
			break;
		}
		rc = trax_readmem(ptrax, data, addr, count);
		/*  If successful, rc == number of bytes read. */
		LOG_DEBUG("TRAX: Read memory: 0x%x [0x%x bytes] rcode=%d", addr, count, (int)rc);
		rc = tpack_send(tchan, 0, packet, &reply.h, 0, data, count, rc, 0, 0, 0, 0);
		if (rc != ERROR_OK)
			LOG_ERROR("TRAX: TPACK_CMD_READMEM: Sending packet returned error %d", rc);
		return rc;
	}

	case TPACK_CMD_WRITEMEM:
	{
		uint32_t chunk;
		addr = ntohl(tpacket->data[0]);
		count = ntohl(tpacket->data[1]);

		if (packet->length < sizeof(tpack_header) + 8 + count) {
			LOG_ERROR("TRAX: writemem packet too small for %d byte request (%d bytes)", count, packet->length);
			rc = ERROR_FAIL;
			break;
		}
		chunk = len - (sizeof(tpack_header) + 8); /* how much we have now to write */
		if (chunk > count)
			chunk = count;
		rc = trax_writemem(ptrax, (uint8_t *)&tpacket->data[2], addr, chunk);
		/*  If successful, rc == number of bytes written.  */
		LOG_DEBUG("TRAX: Write memory: 0x%x [0x%x bytes] rcode=%d", addr, count, (int)rc);
		// TODO: manage multiple packets?
		//target->write_remaining = count - chunk;  /* remaining count to write */
		//target->write_addr = addr + chunk;
		break;
	}

	//TODO: handle TPACK_CMD_FILLMEM?
	default:
	{
		tpack_print_packet(tsock, tchan, "unrecognized request on TRAX channel",
						0, packet, len, 0, 0, 0);
		break;
	}
	}

	rc = tpack_send(tchan, 0, packet, &reply.h, 0, 0, 0, rc, 0, 0, 0, 0);
	if (rc != ERROR_OK)
		LOG_ERROR("TRAX: Sending packet returned error %d", rc);
	return 0;
}

static void set_ram_size(struct trax *ptrax)
{
	uint32_t start_addr = 0;
	uint32_t end_addr = 0 /* trace RAM size */;

	ptrax->source.dm_readreg(ptrax->target, TRAX_REG_MEMADDRSTART, &start_addr);
	ptrax->source.dm_readreg(ptrax->target, TRAX_REG_MEMADDREND, &end_addr);
	ptrax->ram_size = start_addr - end_addr;

	ptrax->start_addr = start_addr;
	ptrax->end_addr   = end_addr;
}

/* This is a general function used to check if wraparound has occurred.
 * It is used by trax_accessmem, so that when a track of the expected
 * address is kept, the software is aware of wraparound conditions
 *
 * address  : contains address that is passed pre-increment. After
 *            increment is done and appropriate calculations for
 *            wraparound have been made, it contains the value post
 *            increment
 */
static void increment_address(struct trax *ptrax, uint32_t *address)
{
	uint32_t trax_mask = ptrax->end_addr;
	uint32_t old_address = *address;
	uint32_t wrapcnt = 0;

	/* Keep track of the wrap arounds that have already occurred */
	wrapcnt = (old_address & TRAX_ADDRESS_WRAPCNT) >> TRAX_ADDRESS_WRAP_SHIFT;

	/* If we reach the endaddr, the next address would be the startaddr, along
	 * with an increment in the wrap count */
	if ((old_address & trax_mask) == (ptrax->end_addr & trax_mask))
		*address = (ptrax->start_addr | ((wrapcnt + 1) << TRAX_ADDRESS_WRAP_SHIFT));
	else
		*address = old_address + 1;
	LOG_DEBUG("TRAX: New TRAXADDR: 0x%x", *address);
}


static int trax_accessmem(struct trax *ptrax,
		uint8_t *data, uint32_t tram_addr,
		uint32_t len, uint32_t read)
{
	uint32_t status, bytes;
	uint32_t saved_address, check_address, address;
	uint32_t retry_cnt = 0;
	uint32_t *ptr = (uint32_t *)data;	// TODO: handle host endianness...

	LOG_DEBUG("TRAX: Set Memory Size");
	set_ram_size(ptrax);

	LOG_DEBUG("TRAX: Read Status register");
	ptrax->source.dm_readreg(ptrax->target, TRAX_REG_TRAXSTAT, &status);

	if (status & TRAX_STATUS_TRACT) {
		LOG_ERROR("TRAX: Memory access attempted while trace active");
		return ERROR_FAIL;
	}

	LOG_DEBUG("TRAX: Save Address register");

	ptrax->source.dm_readreg(ptrax->target, TRAX_REG_TRAXADDR, &saved_address);

	address = tram_addr / 4;

	LOG_DEBUG("TRAX: Write 0x%x to TRAX_REG_TRAXADDR (saved:0x%x)", address, saved_address);
	ptrax->source.dm_writereg(ptrax->target, TRAX_REG_TRAXADDR, address);

	for (bytes = 0; bytes < len;) {
		uint32_t cur_data;

		if (read) {
			if (ptrax->source.dm_readreg(ptrax->target, TRAX_REG_TRAXDATA, &cur_data) != ERROR_OK) {
				LOG_ERROR("TRAX: read TRAXDATA register failed. Abort");
				break;
			}
			if (ptrax->is_xtensa) {
				if (ptrax->source.dm_readreg(ptrax->target, TRAX_REG_TRAXSTAT, &status) != ERROR_OK) {
					LOG_ERROR("TRAX: read TRAXSTAT register failed. Abort");
					break;
				}

				if (status & TRAX_STATUS_BUSY) {
					if (retry_cnt++ == RETRY_MAX) {
						LOG_ERROR("TRAX: Maximum retry count reached. Abort");
						break;
					}
					continue;
				}
			}

			// success
			retry_cnt = 0;
			*ptr++ = cur_data;
			bytes += 4;
			increment_address(ptrax, &address);
		} else {
			if (ptrax->source.dm_writereg(ptrax->target, TRAX_REG_TRAXDATA, *ptr++) != ERROR_OK) {
				LOG_ERROR("TRAX: write TRAXDATA register failed. Abort");
				break;
			}
			bytes += 4;
			increment_address(ptrax, &address);
		}
	}
	LOG_DEBUG("TRAX: Total bytes %s = %d", (read ? "read" : "write"), bytes);

	/*  Check whether address got updated as expected.  */

	ptrax->source.dm_readreg(ptrax->target, TRAX_REG_TRAXADDR, &check_address);

	if (address != check_address) {
		LOG_ERROR("TRAX: Expected address(0x%x) differs trax address (0x%x)!", address, check_address);
		return ERROR_FAIL;	/* bad address check */
	}
	LOG_DEBUG("TRAX: Expected address (0x%x) OK", address);

	/* Finally, restore the address register  */
	LOG_DEBUG("TRAX: Restore Trax Address register");
	ptrax->source.dm_writereg(ptrax->target, TRAX_REG_TRAXADDR, saved_address);
	return bytes;
}

static int trax_readmem(struct trax *ptrax, uint8_t *data, uint32_t addr, uint32_t count)
{
	return trax_accessmem(ptrax, data, addr, count, 1);
}

static int trax_writemem(struct trax *ptrax, uint8_t *data, uint32_t addr, uint32_t count)
{
	return trax_accessmem(ptrax, data, addr, count, 0);
}
