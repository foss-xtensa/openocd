/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Copyright (C) 2006-2023 by Cadence Design Systems, Inc.
 */

/*
 *  TPACK is a simple protocol for exchanging messages, including
 *  request/response and other sequences, over a link (typically TCP/IP)
 *  that provides the following:
 *
 *	- in-order transmission (no need for sequence nos to reorder)
 *	- reliable transmission (no seq nos, checksums, auto-acks and retransmission)
 *	- 8-bit clean (no character escaping mechanism)
 *	- byte stream or arbitrarily large packets (no imposed fragmentation;
 *	  however, there is provision for fragmentation to allow better
 *	  or more distributed response times when multiple channels are present,
 *	  e.g. to prevent a GB trace dump from monopolizing the link)
 *
 *  What TPACK does provide on top of this link, is the ability to:
 *
 *	- multiplex multiple channels (e.g. access multiple distinct devices,
 *	  or multiplex many endpoints, or both)
 *
 *	- allow out-of-order responses (e.g. while a wait-for-completion request
 *	  is pending, other requests can be sent, including requests to
 *	  cancel other/all pending requests)
 *
 *	- encapsulate packetization (e.g. length of packet is explicit, not
 *	  inferred from packet type; this, along with version info communicated
 *	  at startup, also allows graceful handling of unknown packet types,
 *	  and better multi-version support)
 *
 *	- each packet indicates whether it is a new request, and whether it
 *	  expects a reply; thus one can send a single packet soliciting no
 *	  response (similar to UDP), a request followed by a reply, a 3-way
 *	  handshake (request, followed by reply, and reply to the reply), etc.
 *
 *	- command number is in all packets (e.g. both request and reply)
 *	  so protocol traffic can more easily be decoded in a stateless manner
 *	  [NO LONGER TRUE]
 *
 *  [[The name TPACK originated from "Trax PACKet" but its use is not limited
 *    to TRAX.  One might also call it "Tensilica PACKet" protocol.]]
 */

#ifndef OPENOCD_TRAX_TPACK_H
#define OPENOCD_TRAX_TPACK_H

#include <stdint.h>


/*  Default port number used to access a TRAX device over the network
 *  (using the tpack-based TRAX protocol):  */
#define TRAX_DEFAULT_PORT	11444

/*  Versions up to RB-200x.x used version 0x01.
 *  RC-20xx.x and later use 0x02.  (Differences are minor, there was just
 *  no need to support communication across versions.)
 */
#define TPACK_VERSION		0x02	/* for tpack_init_packet.version */

#define TPACK_DEFAULT_ALLOC_CHANNELS	16	/* default allocated channel slots per connection */
#define TPACK_DEFAULT_ALLOC_PACKETS		16	/* default allocated packet slots per channel */


/*
 *  FIXME: some of these apply only to TRAX protocol packet commands!
 */
/*  Connection management:  */
#define TPACK_CMD_NOP		0x0000	/* no operation */
#define TPACK_CMD_STARTUP	0x0001	/* version info, exchanged at startup */
#define TPACK_CMD_OPEN		0x0002	/* open a channel */
#define TPACK_CMD_CLOSE		0x0003	/* close a channel */
/*  Generic requests:  */
#define TPACK_CMD_READREG	0x0010	/* read register */
#define TPACK_CMD_WRITEREG	0x0011	/* write register */
#define TPACK_CMD_READMEM	0x0012	/* read memory */
#define TPACK_CMD_WRITEMEM	0x0013	/* write memory */
#define TPACK_CMD_FILLMEM	0x0014	/* fill memory with pattern */
/*  Device-specific requests:  */
/*  TRAX:  */
#define TPACK_CMD_LIST		0x0041  /* list known TRAX devices */

/*  Packet header flags:  */
//#define TPACK_HF_FRAG_CONT	0x1000	/* 0 = first packet fragment, set = continuation packet */
//#define TPACK_HF_FRAG_MORE	0x2000	/* 0 = last packet fragment, set = more packets follow */
#define TPACK_HF_FIRST		0x4000	/* 0 = response, set = initial request (first) */
#define TPACK_HF_MORE		0x8000	/* 0 = no reply expected (last), set = reply (more) expected */


/*  Common types:  */
typedef uint8_t				tpack_u8;
typedef uint16_t			tpack_u16;
typedef int16_t				tpack_i16;
typedef uint32_t			tpack_u32;
typedef int32_t				tpack_i32;
typedef uint64_t			tpack_u64;



/**************************************************************************
 *  Definitions for abtracting calling select()  (see select-utils.c)
 */

/*  Values passed to tpack_select_set_callback()'s <events> parameter:  */
#define TPACK_SEL_READ		1	/* fd is ready for a read (or accept) */
#define TPACK_SEL_WRITE		2	/* fd is ready for a write */
#define TPACK_SEL_EXCEPT	4	/* fd is ready for reading out-of-band data */
#define TPACK_SEL_ALL		7	/* all defined events */


/*
 *  Header for all packets over the socket connection.
 *  Command-specific payload, if any, follows the header.
 *
 *  All fields are transmitted in big-endian byte order.
 *  Internally they are stored in local byte order
 *  (tpack send and receive functions do the header translation, and
 *  command-specific code handles any byte-order swapping of payload data).
 *
 *  Generic packets currently defined include:
 *
 *    send repl
 *    len  len  channel rcode              phas [data...]
 *    ---- ---  ------- -------------      ---  -------------------
 *    16   16   xxx     TPACK_CMD_NOP      xxx  none
 *    20   --   0       TPACK_CMD_STARTUP  1*   min/max versions (see tpack_init_packet)
 *    20+n 20   0       TPACK_CMD_OPEN     2    src_chan target... // src_chan (see tpack_open_packet)
 *    16   --   nn      TPACK_CMD_CLOSE    1*   none  (can get reply or another close? reply to latter??)
 *    20   20   nn      TPACK_CMD_READREG  2    regno // regvalue
 *    24   16   nn      TPACK_CMD_WRITEREG 2    regno regvalue //
 *    24   16+x nn      TPACK_CMD_READMEM  2    addr count // mem...
 *    24+x 16   nn      TPACK_CMD_WRITEMEM 2    addr count mem... //
 *    24?  16   nn      TPACK_CMD_FILLMEM  2    addr count fillvalue //
 *    16   20   0       TPACK_CMD_LIST     2    // num_units
 */
typedef struct {
	tpack_u32	length;		/* length of packet (including header) in bytes */
	tpack_u16	channel;	/* destination channel;
							   selects device/module/etc being addressed;
							   0 is for messages not associated with a channel,
							   e.g. open (channel establishment) messages */
	    /*	src_channel;*/	/* note: source channel is implicit; it is assumed known
							   to the receiver for the given destination channel;
							   note: the reply to a request to open a channel (TPACK_CMD_OPEN)
							   is sent over the channel used to make the request, *not* over
							   the newly created channel (the source channel for the newly
							   opened channel is encoded in the open request data) */
	tpack_u16	flags;		/* TPACK_HF_xxx */
	tpack_u16	srcid;		/* source request ID (always valid) */
	tpack_u16	dstid;		/* destination request ID, to match request and response
							   where requests can be processed out-of-order; stays
							   same in a packet sequence (eg. request/response)
							   and among fragments of a packet; 0 for TPACK_HF_FIRST */
	tpack_i32	rcode;		/* on request: request/command code (TPACK_CMD_xxx)
							   on reply:   return code, which is either:
							   a negated error code (range -1 .. -4096)
							   or a successful return value (remaining range) */
} tpack_header;

#define TPACK_HEADER_SIZE	sizeof(tpack_header)

/*  Returns true if -4096 <= rcode <= -1 :  */
#define TPACK_IS_ERROR(rcode)	((tpack_u32)(rcode) >= (tpack_u32)-4096)

#define TPACK_DEFAULT_RX_BUFLEN	65536


/*  Packet sent first by both sides of a tpack connection:  */
typedef struct {
	tpack_header	h;
	tpack_u8	min_version;	/* lowest recognized version (typically TPACK_VERSION) */
	tpack_u8	max_version;	/* highest recognized version (typically TPACK_VERSION) */
	tpack_u8	reserved1[2];
} tpack_init_packet;

/*  Packet sent to open a channel:  */
/*  FIXME: how does one operate on multiple devices at once? (group ops)  */
typedef struct {
	tpack_header	h;
	tpack_u16	src_channel;	/* sender's channel number (in both request and reply) */
	tpack_u16	reserved1;	/* reserved, must be zero when sent, ignored when recv */
	tpack_u16	dest_major;	/* destination/target device "major" number, identifies
							   the kind of device being opened (e.g. TRAX, CPU debug,
							   etc); see TPACK_MAJOR_xxx
							   0 reserved for a "generic" open based only on path info */
	tpack_u16	dest_minor;	/* destination/target device "minor" number, identifies
							   which instance of that kind of device being opened
							   (usually base zero??? depends on device?) */
	/*  Remaining fields are for open request only (not reply).  */
	/*  Remaining bytes are a variable-length string containing name or path information
		needed to completely identify what's being opened for the particular dest_major/minor.
		Includes a null terminator, not considered part of the data but is part of the packet;
		so while the string should normally otherwise not contain any null chars, if it ever
		needs to contain binary data, the binary data would be followed by an ignored null char.  */
} tpack_open_packet;

#define TPACK_MAJOR_GENERIC	0	/* destination based only on path info */
#define TPACK_MAJOR_TRAX	1	/* TRAX unit, minor = 0 .. n-1 (for n units) */

/*  Packet sent to close a channel:  */
typedef struct {
	tpack_header	h;
	tpack_i32	ecode;		/* error code (reason to close channel), 0 if normal */
	/*  Remaining bytes are a variable-length string containing error message?  */
} tpack_close_packet;


/*  Packet big enough for all TRAX commands and replies
	except variable part (mem contents) of memory read/write packets:  */
typedef struct {
	tpack_header	h;
	tpack_u32	data[3];
} trax_packet;


#define TPACK_APMASK	0x00FF	/* mask of active packet index within packet ID */


/*  Forward references.  */
typedef struct tpack_socket	tpack_socket;
typedef struct tpack_channel	tpack_channel;

/*
 *  Callback function type for rx packet dispatch.
 *
 *  For new packets (channel's rx_packet_func), must handle 3 main cases:
 *	pieceno == 0  (rx packets)
 *	pieceno > 0   (continuation data of the last rx packet)
 *	pieceno < 0   (channel closed, -pieceno is error code)
 *  For response packets (apinfo's rx_func):
 *	pieceno == 0  (rx packets)
 *	pieceno > 0   (continuation data of the last rx packet)
 *	pieceno < 0   (channel closed without response, -piece is error code)
 *
 *  On pieceno==0, each rx function must also check (packet->flags & TPACK_HF_MORE)
 *  and issue an error (FIXME: how?!) if it doesn't match whether or not it expects to issue a response.
 *
 *  It's the last piece of a packet if tchan->tsock->rx_remaining <= 0
 *  (otherwise you have to track cumulated len relative to original packet->length).
 *
 *  Note that in the case of a channel closing, both the channel's rx_packet_func
 *  and all outstanding packets' rx_func get called.
 */
typedef int (tpack_rx_fn)(tpack_channel *tchan, void *arg,
				 int pieceno, tpack_header *packet, int len);


/*
 *  Info about an outstanding or active packet...
 *  (to allow tracking multiple outstanding packets on a single channel)
 */
typedef struct {
	tpack_i16	next_free;	/* index of next free active packet  */
	tpack_u8	active;		/* 0 = available (free), 1 = active (in-use) */
	tpack_u8	was_sending;	/* last 0 = received, 1 = sent */
	tpack_u16	local_id;	/* local packet ID */
	tpack_u16	remote_id;	/* remote packet ID (or 0 if unknown) */
	tpack_u16	last_flags;	/* last packet's flags */
	tpack_u16	cycle;		/* number of packets exchanged (continuously)
							   over this same packet ID */
	tpack_i32	first_cmd;	/* initial packet request's cmd code */
	tpack_rx_fn *rx_func;	/* function to call when response to this packet arrives */
	void	*rx_arg;		/* argument to pass to rx_func */
	int		rx_minlen;		/* copied from channel's rx_minlen on first cycle,
							   overrides it for subsequent cycles */
} tpack_apinfo;

/*
 *  Describes a TPACK channel (within a socket connection).
 */
struct tpack_channel {
	tpack_socket	*tsock;	/* socket carrying this channel */
	tpack_u16	channel;	/* incoming channel number (local channel index) */
	tpack_u16	outchannel;	/* outgoing channel number */
	tpack_u16	last_issued_id;	/* local ID last allocated (to new message sent/received) */
	tpack_u8	rx_closed;	/* close received */
	tpack_u8	tx_closed;	/* close sent (channel is released when close sent+recv) */
	tpack_u16	dev_major;	/* major number (type) of opened "device" (TPACK_MAJOR_xxx) */
	tpack_u16	dev_minor;	/* minor number (instance index) of opened "device" */
	tpack_i16	free_apacket;	/* index of first free apackets[] entry, or -1 */
	/*tpack_i16	tail_apacket;*/	/* index of last free apackets[] entry, or -1 */
	int		num_apackets;	/* number of active packets */
	int		alloc_apackets;	/* number of entries in apackets[] */
	tpack_apinfo	*apackets;	/* active packets */
	tpack_apinfo	dapackets[TPACK_DEFAULT_ALLOC_PACKETS];	/* default array of active packets */
	unsigned int	ts_freq;	/* timestamp frequency */
	/*  Callback info:  */
	tpack_rx_fn		*rx_packet_func;	/* callback for received packets */
	void	*rx_packet_arg;	/* callback argument */
	int		rx_minlen;	/* minimum bytes of packet to read (or whole packet
						   if smaller than this) before reporting via callback;
						   MUST be no larger than tsock->rx_buflen
						   (preferably much smaller) */
};


/*
 *  Describes a TPACK socket connection.
 */
struct tpack_socket {
	char	peer_name[256];	/* peer hostname (or IP address) */
	int		peer_port;	/* peer port number */

	/*  Packet reception (RX) state machine:  */
	int		  rx_done;	/* set once EOF or error encountered in input */
	unsigned int  rx_remaining;	/* number of bytes left to read for current rx packet */
	tpack_channel  *rx_channel;	/* (if rx_remaining>0) channel receiving current rx packet;
								   0 if packet being dropped/ignored */
	tpack_apinfo   *rx_apinfo;	/* (if rx_remaining>0) active packet info for current rx
								   packet; 0 if packet being dropped/ignored */
	unsigned int  rx_piece_no;	/* (if rx_remaining>0) next piece of packet to dispatch (0=header) */
	tpack_header  rx_header;	/* (if rx_remaining>0) copy of header of packet being dispatched */
	char		  rx_bufdefault[TPACK_DEFAULT_RX_BUFLEN];	/* default for rx_buf */
	char	  *rx_buf;	/* rx buffer (mostly for servers?) */
	int		  rx_buflen;	/* rx buffer size in bytes */
	char	  *rx_next;	/* (if rx_nextlen > 0) next byte to process in rx buffer */
	int		  rx_nextlen;	/* number of bytes to process in rx buffer */
	/*  Packet transmission (TX) state machine:  */
	int		  tx_done;	/* set once error encountered in output */

	/*  Info on opened channels:  */
	tpack_channel  *gchannel;	/* general channel (channel zero) */
	tpack_channel **channels;	/* array of pointers to channels
				   (includes gchannel at index zero) */
	tpack_channel  *dchannels[TPACK_DEFAULT_ALLOC_CHANNELS];	/* default channel array
				   (pointed to by channels unless allocated dyn.) */
	int		  num_chans;	/* number of active channels, including gchannel */
	int		  alloc_chans;	/* number of entries in channels[] */
	int		  trid;
}; /* tpack_socket */


/*  Flags for tpack_send_receive():  */
#define TPACK_FLAG_RX_MULTIOK	0x0001	/* allow receiving large packets over multiple calls */
#define TPACK_FLAG_RX_DISCARD	0x0002	/* discard portion of rx packet that's too large (UNIMPLEMENTED) */
#define TPACK_FLAG_NOLOG		0x0010	/* don't log warning if remote reply code is non-zero */


/*  Prototypes:  */

tpack_channel	*tpack_receive_process_header(tpack_socket *tsock, tpack_header *packet,
				tpack_apinfo **p_apinfo);
void		tpack_process_receive_packet(tpack_socket *tsock, tpack_channel *tchan, int rc,
				tpack_header *packet, int dispatch_len,
				tpack_rx_fn *rx_func, void *rx_arg);
void		tpack_active_release(tpack_channel *tchan, tpack_apinfo *apinfo);

/*  Channel management functions:  */
extern tpack_channel	*tpack_channel_alloc(tpack_socket *tsock, tpack_rx_fn *rx_func, void *rx_arg,
				int rx_minlen, int chan_struct_size, int outchannel);
extern int	tpack_channel_release(tpack_channel *tchan);
extern int	tpack_channel_open(tpack_channel *gchan, tpack_channel **pchannel,
				tpack_rx_fn *rx_func, void *rx_arg, int rx_minlen,
				int chan_struct_size, int flags,
				tpack_u16 dest_major, tpack_u16 dest_minor, char *dest_path);
extern int	tpack_channel_open_accept(tpack_channel *gchan, tpack_header *packet,
				tpack_channel **pchannel, tpack_rx_fn *rx_func, void *rx_arg,
				int rx_minlen, int chan_struct_size, int flags);
extern int	tpack_channel_close(tpack_channel *tchan, int wait, int ecode, int flags);

/*  Functions specific to a channel within a connection:  */
extern int	tpack_send(tpack_channel *tchan, tpack_apinfo **p_apinfo,
				tpack_header *inreplyto, tpack_header *packet,
				int packetlen, void *tx_data, int tx_datalen, tpack_i32 rcode,
				tpack_rx_fn *rx_func, void *rx_arg, int rx_minlen, int tx_flags);
extern int	tpack_send_receive(tpack_channel *tchan, int cmd, tpack_header *packet,
				int tx_packetlen, void *tx_data, int tx_datalen,
				int rx_minlen,    void *rx_data, int rx_datalen, int flags);

/*  Misc:  */
extern int	tpack_print_packet(tpack_socket *tsock, tpack_channel *tchan, const char *prefix,
				tpack_apinfo *apinfo, tpack_header *packet, int packetlen,
				void *pdata, int pdatalen, int sent);

#endif /* OPENOCD_TRAX_TPACK_H */

