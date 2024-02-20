// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2006-2023 by Cadence Design Systems, Inc.
 */

/* TRAX packet protocol framework (not specific to TRAX!) */

#if defined(_WIN32) || defined(__MSYS__) || defined(__CYGWIN__)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include <helper/log.h>

#include "tpack.h"

/*  For Solaris:  */
#ifndef INADDR_NONE
#define INADDR_NONE	((in_addr_t)-1)
#endif


int _tpack_debug_msgs;			// FIXME: use logging option hooks
int _tpack_debug_track_msgs;	// FIXME: use logging option hooks
int _tpack_debug_channel_msgs;	// FIXME: use logging option hooks

extern int send_bytes(tpack_socket *tsock, unsigned char *buffer, int length);


/*
 *  Return name of specified command, or "?nnn?" if not recognized
 *  (in a non-reentrant global buffer).
 */
static const char  *tpack_cmd_name(tpack_i32 cmd)
{
	static char tpack_tmpcmdname[14];

	switch (cmd) {
	case TPACK_CMD_NOP:			return "nop";
	case TPACK_CMD_STARTUP:		return "startup";
	case TPACK_CMD_OPEN:		return "open";
	case TPACK_CMD_CLOSE:		return "close";
	case TPACK_CMD_READREG:		return "readreg";
	case TPACK_CMD_WRITEREG:	return "writereg";
	case TPACK_CMD_READMEM:		return "readmem";
	case TPACK_CMD_WRITEMEM:	return "writemem";
	case TPACK_CMD_FILLMEM:		return "fillmem";
	case TPACK_CMD_LIST:		return "list";
	default:
		sprintf(tpack_tmpcmdname, "?%ld?", (long)cmd);
		return tpack_tmpcmdname;
	}
}


/*
 *  Display specified packet in human-readable format.
 *  The header part of the packet is assumed to have been already
 *  converted in native (host) byte order; the rest is usually still
 *  in network byte order.
 *
 *  Parameters:
 *	tsock		socket over which packet sent or received
 *	tchan		channel over which packet sent or received, 0 if unknown
 *	prefix		string to display before other info in log line, 0 or "" if none
 *	apinfo		packet exchange tracking info, 0 if unknown
 *	packet		packet to display
 *	packetlen	number of bytes available at *packet (if 0, default to size of header)
 *	pdata		extra packet data payload, 0 if none
 *	pdatalen	number of bytes in extra packet data payload, 0 if none
 *	sent		0 = received packet, 1 = sent packet
 */
int  tpack_print_packet(tpack_socket *tsock, tpack_channel *tchan, const char *prefix,
			tpack_apinfo *apinfo, tpack_header *packet, int packetlen,
			void *pdata, int pdatalen, int sent)
{
	tpack_u16 channel = packet->channel, flags = packet->flags;
	tpack_u16 srcid = packet->srcid, dstid = packet->dstid;
	tpack_u16 locid = (sent ? srcid : dstid);
	tpack_i32 length = packet->length, rcode = packet->rcode;
	char showdata[50];	/* enough space for "## ## ## ##  ## ## ## ##  ## ## ## ## ..." */
	char locchan[12], remchan[12], showrcode[20];
	int i;

	if ((flags & TPACK_HF_FIRST) != 0 && !sent) {	/* dstid always 0 for 1st packet of a transaction */
		if (apinfo != 0)
			locid = apinfo->local_id;
	} else if (apinfo == 0 && tchan != 0) {
		apinfo = &tchan->apackets[locid & (tchan->alloc_apackets - 1)];	/* active packet */
		if (apinfo->local_id != locid || !apinfo->active)
			apinfo = 0;		/* not a recognized active packet */
	}
	if (packetlen == 0)
		packetlen = sizeof(tpack_header);
	showdata[0] = 0;
	if (packetlen + pdatalen > (int)sizeof(tpack_header))	/* data to display? */
		for (i = sizeof(tpack_header); i < length; i++) {
			if (i >= (int)sizeof(tpack_header) + 12 || i >= packetlen + pdatalen) {
				strcat(showdata, " ...");
				break;
			}
			if (i > (int)sizeof(tpack_header))
				strcat(showdata, ((i & 3) == 0) ? "  " : " ");
			sprintf(showdata + strlen(showdata), "%02x",
				(i < packetlen) ? ((unsigned char *)packet)[i] : ((unsigned char *)pdata)[i - packetlen]);
		}
	/*  Channel numbers (properly handle invalid packets too):  */
	if (!sent)
		sprintf(locchan, "%02d", channel);
	else if (tchan)
		sprintf(locchan, "%02d", tchan->channel);
	else
		strcpy(locchan, "??");
	if (sent)
		sprintf(remchan, "%02d", channel);
	else if (tchan)
		sprintf(remchan, "%02d", tchan->outchannel);
	else
		strcpy(remchan, "??");
	/*  Return code:  */
	strcpy(showrcode, "");
	if ((flags & TPACK_HF_FIRST) == 0)
		sprintf(showrcode, " rcode=%ld", (long)rcode);	// FIXME: show error string if in range -4096 .. -1
	if (prefix == 0)
		prefix = "";

	LOG_DEBUG("%s:%d loc-ch%s.id%04X / rem-ch%s.id%04X %c%d - %s%s%s (%4d bytes) %s%s [%s]",
		tsock->peer_name, tsock->peer_port,
		locchan, locid, remchan, (sent ? dstid : srcid),
		(apinfo ? '#' : '?'), (apinfo ? apinfo->cycle : 0),
		prefix, (prefix[0] ? ": " : ""),
		((flags & TPACK_HF_FIRST)
		? ((flags & TPACK_HF_MORE) ? "cmd  " : "uacmd")
		: ((flags & TPACK_HF_MORE) ? "resp." : "reply")),
		length,
		((flags & TPACK_HF_FIRST) ? tpack_cmd_name(rcode)
		: apinfo ? tpack_cmd_name(apinfo->first_cmd) : "cmd=???"),
		showrcode, showdata
		);
	return 0;
}


/*
 *  Track packet just received or about to be sent.
 *  Keeps track of the outstanding request (packet exchange) of which it is part.
 *  This function allocates a packet transaction ID if necessary
 *  and verifies that the packet exchange protocol is followed.
 *
 *  The protocol is symmetrical so most of the code applies to both sending and receiving.
 *
 *  If successful, returns pointer to tracking info;
 *  caller must call tpack_active_release() once done with the packet
 *  (usually once entire packet sent or received).
 *  Returns 0 otherwise, i.e. if any protocol violation detected.
 *
 *  Parameters:
 *	tchan		channel over which packet is transported
 *	flags		packet flags
 *	locid		local packet ID:  sending: dstid of packet responded to, 0 if new
 *					  receiving: packet dstid (usually 0 if new)
 *	remid		remote packet ID: sending: srcid of packet responded to, 0 if new
 *					  receiving: packet srcid
 *	sending		0=received packet, 1=packet about to be sent
 */
tpack_apinfo *tpack_active_track(tpack_channel *tchan, tpack_u16 flags,
			tpack_u16 locid, tpack_u16 remid, tpack_i32 rcode, int sending)
{
	tpack_socket *tsock = tchan->tsock;
	tpack_apinfo *apinfo;
	tpack_i16 index;

	/*  Keep track of active packets, allocate ID for new ones:  */
	if ((flags & TPACK_HF_FIRST) == 0) {
		/*  Existing packet exchange:  */
		const char *what = sending ? "sending in response to" : "received";

		index = (locid & TPACK_APMASK);
		apinfo = &tchan->apackets[index];

		/*  The first response also generated an ID, pick it up here:  */
		if (!sending && apinfo->cycle == 1 && apinfo->remote_id == 0)
			apinfo->remote_id = remid;	/* first response on this message stream, capture remote ID */
		if (sending && apinfo->cycle == 1 /*&& locid == 0*/)
			locid = apinfo->local_id;

		/*  Check validity of IDs, and ordering:  */
		if (!apinfo->active) {
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X / rem-ch%02d.id%04X %s packet with inactive ID",
				tsock->peer_name, tsock->peer_port, tchan->channel, locid, tchan->outchannel, remid, what);
			return 0;		/* packet with inactive ID */
		}
		if (sending == apinfo->was_sending) {
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X / rem-ch%02d.id%04X %s the same ID twice-in-a-row in same transaction (rcode=%d)",
				tsock->peer_name, tsock->peer_port, tchan->channel, locid, tchan->outchannel, remid,
				what, rcode);
			return 0;		/* two packets sent/recv in a row over same ID -- must alternate */
		}
		if (apinfo->local_id != locid) {
			LOG_DEBUG("%s:%d loc-ch%02d.id**** / rem-ch%02d.id%04X %s packet with mismatched local ID 0x%04X expected 0x%04X",
				tsock->peer_name, tsock->peer_port, tchan->channel, tchan->outchannel, remid,
				what, locid, apinfo->local_id);
			return 0;		/* packet with mismatching local ID */
		}
		if (apinfo->remote_id != remid) {
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X / rem-ch%02d.id**** %s packet with mismatched remote ID 0x%04X expected 0x%04X",
				tsock->peer_name, tsock->peer_port, tchan->channel, locid, tchan->outchannel,
				what, remid, apinfo->remote_id);
			return 0;		/* packet with mismatching remote ID */
		}

		apinfo->cycle++;
	} else {
		/*  New packet exchange:  */
		if (!sending && locid != 0)
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X / rem-ch%02d.id%04X warning: received new packet with non-zero dstid (0x%04X)",
				tsock->peer_name, tsock->peer_port, tchan->channel, locid, tchan->outchannel, remid,
				locid);

		/*  Find an unused active packet ID slot:  */
		index = tchan->free_apacket;
		if (index < 0) {
			//  TODO:  grow tchan->apackets[] as needed, eg. double in size when running out.
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X / rem-ch%02d.id%04X can't %s packet, too many (%d) active outstanding (cmd=%s)",
				tsock->peer_name, tsock->peer_port, tchan->channel, locid, tchan->outchannel, remid,
				(sending ? "send" : "receive"), tchan->num_apackets, tpack_cmd_name(rcode));
			return 0;		/* too many active packets (outstanding requests) on this connection */
		}
		apinfo = &tchan->apackets[index];

		/*
		*  Setup the apinfo entry regardless of whether it stays active (allocated).
		*  The caller will use it temporarily even if not active (until next packet
		*  sent or received, at most).
		*
		*  Issue a new local ID regardless (so one-shot packets also get their own ID).
		*  The bottom bits are the index, and the top bits increment for each new packet
		*  sent or received.  We also ensure a valid ID is never zero.
		*/
		locid = ((tchan->last_issued_id + (TPACK_APMASK + 1)) & ~TPACK_APMASK) + index;
		if (locid == 0)
			locid = TPACK_APMASK + 1;	/* increment once more to avoid zero ID */
		apinfo->local_id = locid;
		apinfo->remote_id = remid;
		apinfo->first_cmd = rcode;
		apinfo->cycle = 1;		/* first packet of exchange */
		if (!sending && rcode == TPACK_CMD_STARTUP &&
			tchan->last_issued_id == TPACK_APMASK + 1 && tchan->channel == 0) {
			/* special case for startup exchange, keep same rx_func */
			//LOG_DEBUG("kept rx_func=0x%x", apinfo->rx_func);
		} else {
			apinfo->rx_func = tchan->rx_packet_func;
			apinfo->rx_arg = tchan->rx_packet_arg;
			apinfo->rx_minlen = tchan->rx_minlen;
			//LOG_DEBUG("set rx_func=rx_packet_func=0x%x", apinfo->rx_func);
		}
		tchan->last_issued_id = locid;

		/*  Make the packet transaction ID active (outstanding request):  */
		tchan->free_apacket = apinfo->next_free;
		apinfo->next_free = 0xFFFF;
		apinfo->active = 1;
		tchan->num_apackets++;
	}
	apinfo->last_flags = flags;
	apinfo->was_sending = sending;
	if (_tpack_debug_track_msgs)
		LOG_DEBUG("%s:%d loc-ch%02d.id%04X tracked (%s first=%d last=%d)",
			tsock->peer_name, tsock->peer_port, tchan->channel, locid,
			(sending ? "sending" : "receiving"),
			(flags & TPACK_HF_FIRST) ? 1 : 0, (flags & TPACK_HF_MORE) ? 0 : 1);

	return apinfo;
}


/*
 *  Call this when done with a packet successfully tracked by tpack_active_track().
 *  This function frees the packet transaction ID if it was the last packet
 *  of its sequence (of a packet exchange).
 *
 *  Returns 0 if any protocol violation detected, pointer to tracking info otherwise.
 *
 *  Parameters:
 *	tchan		channel over which packet is transported
 *	apinfo		packet transaction tracking info returned by tpack_active_track()
 */
void  tpack_active_release(tpack_channel *tchan, tpack_apinfo *apinfo)
{
	tpack_i16 index = (apinfo->local_id & TPACK_APMASK);
	tpack_u16 flags = apinfo->last_flags;

	if ((flags & TPACK_HF_MORE) == 0) {	/* last packet of exchange? */
		apinfo->active = 0;		/* no longer active */
		apinfo->next_free = tchan->free_apacket;
		tchan->free_apacket = index;
		tchan->num_apackets--;
		if (_tpack_debug_track_msgs)
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X released",
				tchan->tsock->peer_name, tchan->tsock->peer_port, tchan->channel, apinfo->local_id);
	} else if (_tpack_debug_track_msgs)
		LOG_DEBUG("%s:%d loc-ch%02d.id%04X kept",
			tchan->tsock->peer_name, tchan->tsock->peer_port, tchan->channel, apinfo->local_id);
}


/*
 *  Send a packet over the specified connection.
 *  (This is a blocking call.)
 *  Parameters:
 *	tchan		channel over which to send packet
 *	*p_apinfo	...
 *	inreplyto	0 for initial request, else ptr to packet (header) being replied to
 *			(note: TPACK_HF_FIRST flag automatically set if inreplyto == 0);
 *			when replying to TPACK_CMD_OPEN requests, inreplyto MUST point to
 *			enough data past the header to contain the source channel number
 *	packet		packet to send, points to packetlen bytes to send (of which header
 *			is undefined, filled by this function); may be same as inreplyto
 *	packetlen	length in bytes of packet to send, including header, not tx_data/tx_datalen
 *			(if 0, default to sizeof(tpack_header))
 *	tx_data		pointer to extra payload data, 0 if none
 *	tx_datalen	length of extra payload data, 0 if none
 *			(effective packet length is packetlen + tx_datalen)
 *	rcode		command request code if inreplyto == 0,
 *			return code otherwise (-1 .. -4096 is negated error code, else is success)
 *	rx_func		0 if no response expected, else function to call upon receiving response
 *			(note: TPACK_HF_MORE flag automatically set if rx_func != 0)
 *	rx_arg		argument passed to rx_func
 *	rx_minlen	minimum number of packet bytes to receive before invoking rx_func w/rc==0
 *			(if 0, use sizeof(tpack_header) as a default)
 *	tx_flags	lower 16 bits are packet header flags (TPACK_HF_xxx),
 *			upper 16 bits are optional tpack_send() flags (none currently defined)
 *			(TPACK_HF_FIRST, TPACK_HF_MORE automatically set per inreplyto, rx_func)
 *
 *  On return:
 *	packet->id ...?
 *
 *  Returns 0 upon success, error code otherwise (e.g. invalid parameters,
 *  tpack_active_track() error, send() error or incomplete, tx_done set [previous send() error], ...).
 *  NOTE:  errors are unexpected, callers may terminate the whole socket if one is returned.
 */
int  tpack_send(tpack_channel *tchan, tpack_apinfo **p_apinfo,
			tpack_header *inreplyto, tpack_header *packet,
			int packetlen, void *tx_data, int tx_datalen, tpack_i32 rcode,
			tpack_rx_fn *rx_func, void *rx_arg, int rx_minlen, int tx_flags)
{
	tpack_socket *tsock = tchan->tsock;
	tpack_u16 channel = tchan->outchannel, locid, remid;
	tpack_u32 length;
	tpack_apinfo *apinfo;
	int rc;

	if (p_apinfo)
		*p_apinfo = 0;
	if (packetlen == 0)
		packetlen = sizeof(tpack_header);
	if (packetlen < (int)sizeof(tpack_header) || tx_datalen < 0) {
		LOG_ERROR("TPACK: Invalid packet length");
		return -2;  /* invalid length */
	}
	if (tx_datalen > 0 && tx_data == 0) {
		LOG_ERROR("TPACK:  missing data pointer");
		return -3;  /* missing data pointer */
	}
	length = packetlen + tx_datalen;

	/*  Keep track of active packets, allocate ID for new ones:  */
	if (inreplyto)
		tx_flags &= ~TPACK_HF_FIRST;	/* existing packet exchange */
	else
		tx_flags |= TPACK_HF_FIRST;		/* new packet exchange */
	if (rx_func)
		tx_flags |= TPACK_HF_MORE;		/* response expected */
	/* else last packet of exchange sequence; or if response expected,
	 * use generic rx_func, or caller sets one later via *p_apinfo
	 */
	apinfo = tpack_active_track(tchan, tx_flags,
		(inreplyto ? inreplyto->dstid : 0), (inreplyto ? inreplyto->srcid : 0), rcode, 1);
	if (apinfo == 0) {
		LOG_ERROR("TPACK:  Active track failed");
		return -4;
	}
	locid = apinfo->local_id;
	remid = apinfo->remote_id;
	apinfo->rx_func = rx_func;
	apinfo->rx_arg = rx_arg;
	apinfo->rx_minlen = rx_minlen ? rx_minlen : (int)sizeof(tpack_header);
	//LOG_DEBUG("tpack_send: set rx_func=0x%x", apinfo->rx_func);

	/*  Optionally display before transmission:  */
	if (_tpack_debug_msgs) {
		packet->length  = length;
		packet->channel = channel;
		packet->flags   = tx_flags;
		packet->srcid   = locid;
		packet->dstid   = remid;
		packet->rcode   = rcode;
		tpack_print_packet(tsock, tchan, "send", apinfo, packet, packetlen, tx_data, tx_datalen, 1);
	}

	/*  Put packet in standard network byte-order before transmitting:  */
	packet->length  = htonl(length);
	packet->channel = htons(channel);
	packet->flags   = htons(tx_flags);
	packet->srcid   = htons(locid);
	packet->dstid   = htons(remid);
	packet->rcode   = htonl(rcode);

	/*  FIXME: should keep packet active until last bit of last packet was sent...
		FIXME: actually, sending should be as asynchronous as receiving,
		to avoid possibility of deadlock (when peers send to each other
		on full network buffer queues, neither receiving to empty them) */
	tpack_active_release(tchan, apinfo);

	/*  FIXME: use sendmsg() to avoid unnecessary delay/inefficiency and send
	 *  everything at once, because we've enabled TCP_NODELAY on the connection.
	 *  (note that sendmsg() only available in Linux, not Windows)
	 */

	/*  First send the part that contains the header:  */
	rc = send_bytes(tsock, (unsigned char *)packet, packetlen);
	if (rc != 0) {
		LOG_ERROR("TPACK: Sending bytes failed with error %d", rc);
		/* FIXME: do we need to cancel apinfo, or does caller always close connection anyway? */
		apinfo = 0;
	} else if (tx_datalen > 0) {
		/*  Then any extra data portion:  */
		rc = send_bytes(tsock, tx_data, tx_datalen);
		if (rc != 0) {
			LOG_ERROR("TPACK: Sending bytes failed with error %d", rc);
			/* FIXME: do we need to cancel apinfo, or does caller always close connection anyway? */
			apinfo = 0;
		}
	}
	/*  Restore the header (to native byte order), in case the caller needs it.  */
	packet->length  = length;
	packet->channel = channel;
	packet->flags   = tx_flags;
	packet->srcid   = locid;
	packet->dstid   = remid;
	packet->rcode   = rcode;
	if (p_apinfo)
		*p_apinfo = apinfo;
	return rc;
}


/*
 *  Process header of a received packet, including fixing endianness
 *  of header members.
 *  (This is a non-blocking call.)
 *
 *  Parameters:
 *	tsock		socket over which packet was received
 *	packet		packet header
 *	p_apinfo	returns packet transaction tracking handle; if non-zero
 *			(only possible if this function is successful),
 *			caller must call tpack_active_release() after entire packet
 *			is received (or processed; but not before calling this
 *			function again on the same socket)
 *
 *  Returns ptr to channel if okay, or 0 if an error was encountered
 *  (FIXME: how to distinguish those that result in dropping the connection?).
 */
tpack_channel  *tpack_receive_process_header(tpack_socket *tsock, tpack_header *packet,
						tpack_apinfo **p_apinfo)
{
	tpack_i32 length  = ntohl(packet->length);
	tpack_u16 channel = ntohs(packet->channel);
	tpack_u16 flags   = ntohs(packet->flags);
	tpack_u16 remid   = ntohs(packet->srcid);
	tpack_u16 locid   = ntohs(packet->dstid);
	tpack_i32 rcode   = ntohl(packet->rcode);
	tpack_channel *tchan;
	tpack_apinfo *apinfo;

	if (p_apinfo)
		*p_apinfo = 0;

	/*  Fix header endianness (convert from network to host/native byte-order):  */
	packet->length  = length;
	packet->channel = channel;
	packet->flags   = flags;
	packet->srcid   = remid;
	packet->dstid   = locid;
	packet->rcode   = rcode;

	/*  Check length:  */
	if (length < (int)sizeof(tpack_header)) {
		LOG_DEBUG("%s:%d - received invalid header length (%d)",
			tsock->peer_name, tsock->peer_port, length);
		tsock->rx_done = -1;	/* can't recover from this... */
		return 0;
	}

	// LOG_DEBUG("expecting %d bytes", tsock->rx_remaining);

	/*  Identify channel:  */
	tchan = tsock->channels[channel];
	if (channel >= tsock->alloc_chans || tchan == 0) {
		fprintf(stderr, "**** bad channel=%d alloc=%d\n", channel, tsock->alloc_chans);
		tpack_print_packet(tsock, 0, "invalid channel on recv", 0, packet, 0, 0, 0, 0);
		/*  Just drop the packet.  */
		return 0;
	}

	/*  Check whether channel is closing.  */
	if (tchan->rx_closed) {
		tpack_print_packet(tsock, 0, "unexpected packet after channel close recv", 0, packet, 0, 0, 0, 0);
		/*  Just drop the packet.  */
		return 0;
	}

	/*  Keep track of active packets, allocate ID for new ones:  */
	apinfo = tpack_active_track(tchan, flags, locid, remid, rcode, 0);
	if (apinfo == 0)
		return 0;	/*  Just drop the packet.  */

	/*  Little cheat, to make things easier -- adjust received packet dstid with correct value:  */
	if (apinfo->cycle == 1)
		packet->dstid = apinfo->local_id;

	if (p_apinfo)
		*p_apinfo = apinfo;
	else
		tpack_active_release(tchan, apinfo);

	/* if (_tpack_debug_msgs)
		tpack_print_packet(tsock, tchan, "recv", apinfo, packet, 0, 0, 0, 0); */

	return tchan;
}


/*
 *  Process incoming rx packet on a tpack socket.
 *
 *  Called by tpack_process_receive() when a whole packet (or with at least
 *  the minimum number of bytes required for the channel) was received.
 */
void  tpack_process_receive_packet(tpack_socket *tsock, tpack_channel *tchan, int rc,
						tpack_header *packet, int dispatch_len,
						tpack_rx_fn *rx_func, void *rx_arg)
{
	/*  Handle close specially here.  */

	if (tchan->rx_closed) {
		/*  Protocol violation:  receiving packet on closed channel.  */
		LOG_DEBUG("%s:%d loc-ch%02d.id%04X received packet on rx-closed channel",
			tsock->peer_name, tsock->peer_port, tchan->channel, packet->dstid);
		tsock->rx_channel = 0;  /* if rx_remaining, mark packet as being dropped */
		tsock->rx_apinfo = 0;   /* ditto */
		/*tpack_sock_close(tsock);*/
	} else if (rc == 0 && (packet->flags & TPACK_HF_FIRST) != 0
				&& packet->rcode == TPACK_CMD_CLOSE) {
		/*  Channel closing, process that generically here.  */
		/*  Adjust all state before calling callback, to give it most freedom as to
		 *  what it can do.  Except only set rx_closed *after* we call it, to keep the
		 *  channel structure active while we do the call.  */
		tsock->rx_channel = 0;  /* if rx_remaining, mark packet as being dropped */
		tsock->rx_apinfo = 0;   /* ditto */
		/*  Notify channel of closing.  */
		/*  (FIXME: set something to prevent blocking / setting rx_closed in this callback?)  */
		(*tchan->rx_packet_func)(tchan, tchan->rx_packet_arg, -1, packet, dispatch_len);
		tchan->rx_closed = 1;		/* close rx side */
		if (tchan->tx_closed) {		/* (rx_packet_func may call tpack_channel_close) */
			/*  Both rx and tx closed, release the channel.  */
			tpack_channel_release(tchan);
		}
	} else {
		/*  Notify channel (or packet response handler) of normal packet reception:  */
		if (rx_func == 0) {
			rx_func = tchan->rx_packet_func;
			rx_arg  = tchan->rx_packet_arg;
		}
		(*rx_func)(tchan, rx_arg, rc, packet, dispatch_len);
	}
	/*  Above callbacks might close channel, etc, so do nothing afterwards (here).  */
}


/*  For use by tpack_receive_reply() and its tpack_rx_response()  */
typedef struct {
	tpack_header   *rx_packet;	/* rx packet */
	int				rx_minlen;	/* min. number of packet bytes, that go in rx_packet */
	tpack_u8	   *rx_data;	/* remainder of packet (data) */
	int				rx_datalen;	/* max length of rx_data */
	int				done;		/* set when entire response received */
	int				err;		/* whether an error occurred (channel closed),
								   once done != 0 */
} tpack_rx_resp_info;

/*
 *  Handle response packet in simple send-receive sequence.
 *  Used by tpack_receive_reply() for its rx_func.
 */
int  tpack_rx_response(tpack_channel *tchan, void *arg, int pieceno, tpack_header *packet, int len)
{
	tpack_socket *tsock = tchan->tsock;
	tpack_rx_resp_info *info = (tpack_rx_resp_info *)arg;
	int rx_minlen = info->rx_minlen;

	if (pieceno < 0) {		/* error, channel closed before complete response received */
		//LOG_ERROR("TPACK: channel closed before complete response receive");
		tpack_channel_close(tchan, 0, 0, 0);	/* acknowledge channel closure */
		info->done = 1;			/* tell event loop it's done */
		info->err = 1;			/* with error condition */
		return 0;
	}

	if (pieceno == 0) {		/* start of packet arrived... */
		if ((packet->flags & TPACK_HF_MORE) != 0) {
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X received reply should not expect response",
				tsock->peer_name, tsock->peer_port, tchan->channel, packet->dstid);
			goto error;
		}
		if ((int)packet->length < rx_minlen) {
			if (!TPACK_IS_ERROR(packet->rcode)) {	/* if successful, must be big enough */
				LOG_DEBUG("%s:%d loc-ch%02d.id%04X received reply too small (%d bytes, expected %d..%d)",
					tsock->peer_name, tsock->peer_port, tchan->channel, packet->dstid,
					packet->length, rx_minlen, rx_minlen + info->rx_datalen);
				goto error;
			}
			rx_minlen = packet->length;
		}
		if ((int)packet->length > rx_minlen + info->rx_datalen) {
			LOG_DEBUG("%s:%d loc-ch%02d.id%04X received reply too big (got %d bytes, expected %d..%d)",
				tsock->peer_name, tsock->peer_port, tchan->channel, packet->dstid,
				packet->length, rx_minlen, rx_minlen + info->rx_datalen);
			goto error;
		}
		/*  Copy packet header.  */
		memcpy(info->rx_packet, packet, rx_minlen);
		len -= rx_minlen;
		packet = (tpack_header *)((char *)packet + rx_minlen);  /* packet += rx_minlen */
	}

	/*  For either start or subsequent piece of packet, handle extra payload...  */

	/*  Copy extra payload.  */
	if (len) {
		memcpy(info->rx_data, packet, len);
		info->rx_data += len;
	}

	if (tsock->rx_remaining <= 0)	/* last piece of packet? */
		info->done = 1;			/* tell event loop it's done */
	return 0;

error:
	info->done = 1;			/* tell event loop it's done */
	info->err = 1;			/* signal error */

	//  This is how we'd discard the packet instead:
	//		tsock->rx_channel = 0;		/* if rx_remaining, mark packet as being dropped */
	//		tsock->rx_apinfo = 0;		/* ditto */
	//		return 0;
	//
	//  FIXME  For now, DO WE:
	//  *  Close entire connection like this?
	//		tsock->rx_done = 1;     ... FIXME is this sufficient? ...
	//  *  Close entire connection like this?
	// TODO: close socket?
	//  *  Close just the channel, like this?
	//  tpack_channel_close(tchan, 0, -1, 0);

	return -1;
}


/*
 *  Receive a reply.
 *  LIMITATION:  can only be used when no packet is expected back other than the reply.
 *  (This is a blocking call.)
 *
 *  Parameters:
 *	tchan		channel over which to issue the request
 *	apinfo		active packet transaction for which to wait for reply; required,
 *			for setting rx_func
 *	packet		packet buffer used for receive; undefined on entry;
 *			on return, contains rx_minlen bytes of the received packet (including
 *			its header), plus possibly another rx_datalen bytes if rx_data == 0
 *	rx_minlen	minimum length of reply expected (in *packet, including header)
 *	rx_data		pointer to extra payload to receive (past rx_minlen); if 0, extra payload
 *			is in *packet past the first rx_minlen bytes (which includes the header)
 *	rx_datalen	??? maximum length of extra payload expected in reply; if rx_data is 0,
 *			*packet must point to a buffer of at least rx_minlen + rx_datalen bytes,
 *			else rx_data must point to a buffer of at least rx_datalen bytes
 *	flags		combination of flags (TPACK_FLAG_xxx) (none currently relevant):
 *			if TPACK_FLAG_RX_MULTIOK is set (NOT IMPLEMENTED!), received packet's data may exceed
 *				rx_minlen + rx_datalen, in which case the first
 *				rx_minlen + rx_datalen bytes are read, and tpack_receive (NOT IMPLEMENTED!)
 *				must be called directly to obtain subsequent bytes;
 *				otherwise, received packet's data must not exceed that size;
 *			(FUTURE: if TPACK_FLAG_RX_DISCARD, discard any part of rx packet exceeding rx_datalen)
 *			if TPACK_FLAG_NOLOG, don't automatically log warning if remote reply code non-zero
 *
 *  Return value is:
 *	If successful, returns 0 or number of bytes still left to read from packet;
 *	On error, returns a negative value.
 */
int  tpack_receive_reply(tpack_channel *tchan, tpack_apinfo *apinfo, tpack_header *packet,
			int rx_minlen, void *rx_data, int rx_datalen, int flags)
{
	tpack_socket *tsock = tchan->tsock;
	tpack_rx_resp_info info;

	/*  Setup info for receiving response.  */
	if (rx_minlen == 0)
		rx_minlen = sizeof(tpack_header);
	if (rx_data == 0)
		rx_data = (char *)packet + rx_minlen;
	info.rx_packet  = packet;
	info.rx_minlen  = rx_minlen;
	info.rx_data    = rx_data;
	info.rx_datalen = rx_datalen;
	info.done = 0;
	info.err = 0;

	if (apinfo) {
		apinfo->rx_func = &tpack_rx_response;
		apinfo->rx_arg = (void *)&info;
		apinfo->rx_minlen = rx_minlen;
		//LOG_DEBUG("receive_reply: set rx_func=0x%x", apinfo->rx_func);
	} else {
		/*  This is generally only used when closing a channel:  */
		tchan->rx_packet_func = &tpack_rx_response;
		tchan->rx_packet_arg = (void *)&info;
		/*tchan->rx_minlen = rx_minlen;*/
		//LOG_DEBUG("receive_reply: set rx_packet_func=0x%x", tchan->rx_packet_func);
	}

	/*  Wait for reply.  */
	LOG_DEBUG("TODO: TPACK: implement receive reply");

	// TODO: FIXME...
	//while (!info.done) {
	//	if (tpack_select(tsock->selinfo, 1) < 0) {
	//		/*tpack_sock_close(tsock);*/		/* bail out */
	//		tsock->rx_done = 1;
	//		return -1;
	//	}
	//}

	if (TPACK_IS_ERROR(packet->rcode) && (flags & TPACK_FLAG_NOLOG) == 0)
		LOG_DEBUG("%s:%d loc-ch%02d.id%04X error %d returned from server",
			tsock->peer_name, tsock->peer_port, packet->channel, packet->dstid,
			-packet->rcode);
	return info.err ? -1 : 0;
}


/*
 *  Allocate a TPACK channel within a given socket.
 *
 *  The channel number is assigned by this function.
 *  The exact number assigned is unique from other allocated/active
 *  channels but otherwise undefined (except that the very first call
 *  to this function for a newly created tpack_socket gives channel zero...
 *
 *  rx_func, rx_arg	Function (and arg) to call upon receiving packets on this channel
 *			(if rx_func is 0, use &tpack_rx_reject as a default).
 *  rx_minlen		Minimum (header part) size of packets to receive on this channel
 *			(if 0, use sizeof(tpack_header) as a default).
 *
 *  chan_struct_size	Size of the tpack_channel structure to allocate.
 *			It must be at least sizeof(tpack_channel), and is
 *			typically the size of some larger structure that
 *			contains a tpack_channel as its first member.
 *
 *  Returns a pointer to the allocated channel structure, or 0 if malloc fails.
 *
 *  Use tpack_channel_release() to free the returned structure (except for
 *  channel zero).  Normally this is done by calling tpack_channel_close().
 */
tpack_channel  *tpack_channel_alloc(tpack_socket *tsock,
					tpack_rx_fn *rx_func, void *rx_arg, int rx_minlen,
					int chan_struct_size, int outchannel)
{
	tpack_channel *channel, **channels;
	int i, index;

	/*  Make sure at least one channel slot is available.  */
	if (tsock->num_chans == tsock->alloc_chans) {	/* no free channels? */
		/*  Double size of channel array (growing exponentially keeps alloc overhead low):  */
		channels = malloc(tsock->alloc_chans * 2 * sizeof(tpack_channel *));
		if (channels == 0) {
			LOG_DEBUG("%s:%d - out of memory allocating a channel",
				tsock->peer_name, tsock->peer_port);
			return 0;
		}
		tsock->alloc_chans *= 2;  /* double the allocation */
		/*  Copy old array to new, bigger one:  */
		memcpy(channels, tsock->channels, tsock->num_chans * sizeof(tpack_channel *));
		/*  Minimal init of new array entries:  */
		for (i = tsock->num_chans; i < tsock->alloc_chans; i++)
			channels[i] = 0;
		/*  Free old/full array:  */
		if (tsock->channels != tsock->dchannels)	/* can't free dchannels[] */
			free(tsock->channels);
		tsock->channels = channels;
	} else {
		channels = tsock->channels;
	}

	/*  Search for available channel slot.
	 *  Silly linear for now.  Maybe if in the future we use tons of channels,
	 *  we can maintain a free list instead.
	 */
	for (index = 0; channels[index] != 0; index++)
		if (index == tsock->alloc_chans) {
			LOG_DEBUG("%s:%d - internal error: no slot to allocate a channel",
				tsock->peer_name, tsock->peer_port);
			return 0;  /* paranoia - should never happen */
		}

	/*  Allocate the channel structure.  (TODO: allow passing it in as well)  */
	channel = (tpack_channel *)malloc(chan_struct_size);
	if (channel == 0) {
		LOG_DEBUG("%s:%d - out of memory allocating a channel", tsock->peer_name, tsock->peer_port);
		return 0;
	}
	/*  Initialize the packet structure:  */
	memset((char *)channel, 0, chan_struct_size);
	channel->tsock = tsock;
	channel->channel = index;
	channel->outchannel = outchannel;
	/*channel->last_issued_id = 0;*/	/* done by memset */
	/*channel->num_apackets = 0;*/	/* done by memset */
	channel->apackets = channel->dapackets;
	channel->alloc_apackets = TPACK_DEFAULT_ALLOC_PACKETS;

	/*channel->free_apacket = 0;*/	/* done by memset */
	for (i = 0; i < TPACK_DEFAULT_ALLOC_PACKETS - 1; i++)
		channel->dapackets[i].next_free = i + 1;

	channel->dapackets[TPACK_DEFAULT_ALLOC_PACKETS - 1].next_free = -1;
	//    channel->rx_packet_func = rx_func ? rx_func : &tpack_rx_reject;
	channel->rx_packet_func = rx_func;
	channel->rx_packet_arg = rx_arg;
	channel->rx_minlen = rx_minlen ? rx_minlen : (int)sizeof(tpack_header);

	/*  Register the channel in tsock:  */
	tsock->num_chans++;
	channels[index] = channel;

	return channel;
}

/*
 *  Release (free) a TPACK channel allocated using tpack_channel_alloc().
 *
 *  Returns 0 if successful, non-zero on error (e.g. null ptr, not an allocated channel, etc).
 */
int  tpack_channel_release(tpack_channel *tchan)
{
	tpack_socket *tsock;
	int i;

	if (tchan == 0)
		return -1;			/* NULL */
	tsock = tchan->tsock;
	i = tchan->channel;
	if (tsock == 0 || tsock->channels == 0 || tsock->num_chans == 0)
		return -1;			/* NULL something */
	if (i == 0 && !tsock->rx_done)
		return -1;			/* don't release gchannel unless closing socket */
	if (i >= tsock->alloc_chans)
		return -1;			/* invalid channel - index out of range */
	if (tsock->channels[i] != tchan)
		return -1;			/* invalid channel - not registered in this tsock */
	/*  Okay, channel is active and kosher, free it...  */

	if (_tpack_debug_channel_msgs)	/*FIXME*/
		LOG_DEBUG("%s:%d loc-ch%02d.id---- closed channel",
			tsock->peer_name, tsock->peer_port, tchan->channel /*tchan->outchannel*/);

	/*  First, de-register from the socket:  */
	if (tsock->rx_channel == tchan) {
		tsock->rx_channel = 0;
		tsock->rx_apinfo = 0;
	}
	tsock->channels[i] = 0;
	tsock->num_chans--;

	/*  Then free it:  */
	if (tchan->apackets != 0 && tchan->apackets != tchan->dapackets) {
		free(tchan->apackets);
		tchan->apackets = 0;
	}
	tchan->tsock = 0;			/* paranoia, to catch bad code quicker */
	tchan->rx_packet_func = 0;
	tchan->apackets = 0;
	free(tchan);
	return 0;
}


/*
 *  Accept request to open a TPACK channel to a specified device within the target.
 *
 *  packet		Open request packet that was received.
 *
 *  *pchannel		Returned channel structure if successful, else 0.
 *
 *  rx_func, rx_arg	Function (and arg) to call upon receiving packets on this channel
 *			(if rx_func is 0, use &tpack_rx_reject as a default).
 *  rx_minlen		Minimum (header part) size of packets to receive on this channel
 *			(if 0, use sizeof(tpack_header) as a default).
 *
 *  chan_struct_size	Size of the tpack_channel structure to allocate.
 *			It must be at least sizeof(tpack_channel), and is
 *			typically the size of some larger structure that
 *			contains a tpack_channel as its first member.
 *
 *  flags		Currently ignored.
 *
 *  On success, returns 0 and sets *pchannel to the opened channel.
 *  Otherwise returns an error code and clears *pchannel.
 *  Possible errors include running out of memory, error in tpack_send, etc...
 *
 *  Use tpack_channel_close() to close the channel returned in *pchannel.
 *  NOTE:  tpack_sock_close() also calls tpack_channel_close().
 */
int  tpack_channel_open_accept(tpack_channel *gchan, tpack_header *packet, tpack_channel **pchannel,
					tpack_rx_fn *rx_func, void *rx_arg, int rx_minlen,
					int chan_struct_size, int flags)
{
	tpack_socket *tsock = gchan->tsock;
	tpack_channel *tchan;
	tpack_open_packet  *opacket = (tpack_open_packet *)packet;
	int rc;

	*pchannel = 0;

	/*  First, allocate a channel, using remote's indicated channel.
		Note:  Open reply is sent on original (control) channel, not this new one.  */
	tchan = tpack_channel_alloc(tsock, rx_func, rx_arg, rx_minlen, chan_struct_size, ntohs(opacket->src_channel));
	if (tchan == 0) {
		tpack_send(gchan, 0, packet, packet, sizeof(tpack_header), 0, 0, -12 /*XOCD_ENOMEM*/, 0, 0, 0, 0);
		LOG_ERROR("TPACK: Cannot allocate a channel, out of memory");
		return -1;  /* out of memory */
	}

	/*  Send open reply.  */
	opacket->src_channel = htons(tchan->channel);
	opacket->reserved1   = 0;
	opacket->dest_major  = htons(opacket->dest_major);
	tchan->dev_major     = htons(opacket->dest_major);
	opacket->dest_minor  = htons(opacket->dest_minor);
	tchan->dev_minor     = htons(opacket->dest_minor);
	rc = tpack_send(gchan, 0, packet, packet, sizeof(tpack_open_packet), 0, 0, 0, 0, 0, 0, 0);
	if (rc != 0) {
		LOG_ERROR("TPACK: Sending packet failed with error %d", rc);
		tpack_channel_release(tchan);
		return rc;		/* tpack_send already prints out error details (FIXME! not true!) */
	}

	if (_tpack_debug_channel_msgs)	/*FIXME*/
		LOG_DEBUG("%s:%d loc-ch%02d.id%04X / rem-ch%02d.id%04X for loc-ch%02d/rem-ch%02d accept open device %d.%d '%s'",
			tsock->peer_name, tsock->peer_port,
			gchan->channel, packet->srcid, gchan->outchannel, packet->dstid,
			tchan->channel, tchan->outchannel,
			tchan->dev_major, tchan->dev_minor, "");
	*pchannel = tchan;
	return 0;
}


/*
 *  Close a TPACK channel.
 *
 *  Blocking call if 'wait' is set.
 *
 *  This function sends a channel close message to the peer.
 *  After calling this function, the specified channel (tchan) must no longer be used.
 *  NOTE:  if the peer also closed this channel (indicated by call to rx_packet_func with
 *  negative pieceno arg), this function deallocates the channel.
 *  Otherwise, the channel's rx_packet_func handler continues to receive packets until that
 *  indication (after which the channel is deallocated).
 *
 *  The rx_packet_func handler, when called with a negative pieceno arg, normally calls
 *  tpack_channel_close() to confirm channel closure; it's okay for it to do so even when
 *  that results in tpack_channel_close() being called twice on the channel (the 2nd call
 *  has no effect).  NOTE:  the rx_packet_func handler must never make a blocking call,
 *  thus must not call this function with 'wait' set.
 *
 *  IMPLEMENTATION NOTES:
 *
 *  Initiating channel close:
 *  For synchronous use (IMPORTANT CAVEAT:  no packet other than peer's close packet
 *  for the same channel can be expected on the entire socket!),
 *  call with wait==1.  Channel structure is deallocated by this call.
 *  For asynchronous rx delivery, call with wait==0.  You can no longer send packets
 *  after this call, but can continue to receive them.  (*rx_packet_func)()
 *  subsequently will be called with pieceno < 0 to indicate close completion;
 *  channel structure is deallocated after return from that rx_packet_func callback.
 *
 *  Confirming channel close:
 *  Call this function with wait==0.
 *  Synchronous:  after receiving channel close with tpack_receive_reply(), tchan->rx_closed
 *  is set, so 'wait' has no effect.  tpack_channel_close() releases (deallocates) the channel.
 *  Asynchronous:  if called from within the rx_packet_func callback that indicates
 *  channel closing, channel structure is deallocated after return from the callback.
 *  If instead tpack_channel_close() is called subsequently, it deallocates the channel
 *  structure directly.
 *
 *  flags are currently ignored.
 *
 *  Returns 0 or positive tpack_send error code if channel released (deallocated),
 *  and a negative error code otherwise (rx_closed not set and wait not set,
 *  close from peer not yet received).
 *  Note:  errors sending or receiving the close packet do not prevent releasing the channel.
 *
 *  NOTE:  tpack_sock_close() calls this function.
 */
int  tpack_channel_close(tpack_channel *tchan, int wait, int ecode, int flags)
{
	tpack_socket *tsock = tchan->tsock;
	tpack_close_packet  packet;
	int rc;

	if (tsock->rx_done) {
		/*  Whole socket is closing, all channels close automatically, no msg sent.  */
		tchan->tx_closed = 1;  /* !?!!? */
		/*tchan->rx_closed = 1;*/ /* !?!!? */
	} else {
		/*  Send close request.  */
		if (!tchan->tx_closed) {
			packet.ecode = htonl(ecode);
			/*... set some error string too!? ...*/
			rc = tpack_send(tchan, 0, 0, &packet.h, sizeof(tpack_close_packet), 0, 0, TPACK_CMD_CLOSE, 0, 0, 0, 0);
			if (rc != 0) {
				LOG_ERROR("TPACK: Sending packet failed with error %d", rc);
				// TODO: close socket
				return rc;
			}
			tchan->tx_closed = 1;
		}

		if (wait && !tchan->rx_closed) {
			/*  Wait for close message, i.e. for peer to also close this channel.  */
			rc = tpack_receive_reply(tchan, 0, &packet.h, sizeof(tpack_close_packet), 0, 0, flags);
			if (rc != 0) {
				LOG_ERROR("TPACK: Receiving packet reply failed with error %d, closing socket", rc);
				// TODO: close socket
				return rc;
			}
			/*  FIXME FIXME: verify we received the expected packet.  */
			tchan->rx_closed = 1;
		}
		/*if (_trax_protocol_debug)*/	/*FIXME*/
		LOG_DEBUG("close ..., channel %d to %d", tchan->channel, tchan->outchannel);
	}
	if (tchan->rx_closed && tchan->tx_closed) {
		/*  Close both sent and received.  Release the channel.  */
		tpack_channel_release(tchan);
		return 0;
	}
	return -1;
}

