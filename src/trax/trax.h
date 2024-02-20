/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Copyright (C) 2016-2020 by Marc Schink <dev@zapb.de>
 * Copyright (C) 2023 by Cadence Design Systems, Inc.
 *
 * Based on RTT server.
 */

#ifndef OPENOCD_TRAX_TRAX_H
#define OPENOCD_TRAX_TRAX_H

#include <stdint.h>
#include <stdbool.h>

#include <helper/command.h>
#include <target/target.h>

/**
 * Control block ID length in bytes, including the trailing null-terminator.
 */
#define TRAX_CB_MAX_ID_LENGTH   16

/* Control block size in bytes. */
#define TRAX_CB_SIZE            (TRAX_CB_MAX_ID_LENGTH + 2 * sizeof(uint32_t))

/* Channel structure size in bytes. */
#define TRAX_CHANNEL_SIZE       24

/* Minimal channel buffer size in bytes. */
#define TRAX_CHANNEL_BUFFER_MIN_SIZE    2

/* TRAX register offsets kept in APB offsets so they can use the same
 * APIs as what comes across the TPACK socket...
 */
#define TRAX_REG_TRAXID             0x0000
#define TRAX_REG_TRAXCTRL           0x0004
#define TRAX_REG_TRAXSTAT           0x0008
#define TRAX_REG_TRAXDATA           0x000C
#define TRAX_REG_TRAXADDR           0x0010
#define TRAX_REG_TRIGGERPC          0x0014
#define TRAX_REG_PCMATCHCTRL        0x0018
#define TRAX_REG_DELAYCNT           0x001C
#define TRAX_REG_MEMADDRSTART       0x0020
#define TRAX_REG_MEMADDREND         0x0024
#define TRAX_REG_MASK               0x007F

#define TRAX_PSEUDOREG0_W           0x0000
#define TRAX_PSEUDOREG1_RW          0x0002

/* A few TRAX register bit definitions */
#define TRAX_ID_VER_DEF             0x00430000 /* default TRAX version is 4.1 */

#define TRAX_ID_PRODNO_SHIFT        28
#define TRAX_ID_PRODNO_MASK         0xf
#define TRAX_ID_PRODNO_TRAX_XTENSA  0          /* TRAXID.PRODNO value for Xtensa TRAX module */

#define TRAX_STATUS_TRACT           0x00000001
#define TRAX_STATUS_TRIG            0x00000002
#define TRAX_STATUS_PCMTG           0x00000004
#define TRAX_STATUS_BUSY            0x00000008

#define TRAX_ADDRESS_WRAPCNT        0x7FE00000
#define TRAX_ADDRESS_WRAP_SHIFT     21


/** TRAX control block. */
struct trax_control {
	/** Maximum number of up-channels. */
	uint32_t num_up_channels;
	/** Maximum number of down-channels. */
	uint32_t num_down_channels;
};

/** TRAX channel. */
struct trax_channel {
	/** Channel structure address on the target. */
	target_addr_t address;
	/** Channel name address on the target. */
	uint32_t name_addr;
	/** Buffer address on the target. */
	uint32_t buffer_addr;
	/** Channel buffer size in bytes. */
	uint32_t size;
	/**  Write position within the buffer in bytes. */
	uint32_t write_pos;
	/** Read position within the buffer in bytes. */
	uint32_t read_pos;
	/**
	 * Buffer flags.
	 *
	 * @note: Not used at the moment.
	 */
	uint32_t flags;
};

/** TRAX channel information. */
struct trax_channel_info {
	/** Channel name. */
	char *name;
	/** Length of the name in bytes, including the trailing null-terminator. */
	size_t name_length;
	/** Buffer size in bytes. */
	uint32_t size;
	/**
	 * Buffer flags.
	 *
	 * @note: Not used at the moment.
	 */
	uint32_t flags;
};

typedef int (*trax_sink_read)(unsigned int channel, const uint8_t *buffer,
		size_t length, void *user_data);

struct trax_sink_list {
	trax_sink_read read;
	void *user_data;

	struct trax_sink_list *next;
};

/** Channel type. */
enum trax_channel_type {
	/** Up channel (target to host). */
	TRAX_CHANNEL_TYPE_UP,
	/** Down channel (host to target). */
	TRAX_CHANNEL_TYPE_DOWN
};

typedef int (*trax_source_attach)(struct target *target, bool *found, bool *has_jtag);
typedef int (*trax_source_start)(struct target *target, void *user_data);
typedef int (*trax_source_stop)(struct target *target, void *user_data);
typedef int (*trax_source_write)(struct target *target, unsigned int channel,
		const uint8_t *buffer, size_t *length, void *user_data);
typedef int (*trax_source_dm_readreg)(struct target *target, uint32_t regno, uint32_t *value);
typedef int (*trax_source_dm_writereg)(struct target *target, uint32_t regno, uint32_t value);

/** TRAX source. */
struct trax_source {
	trax_source_attach attach;
	trax_source_start start;
	trax_source_stop stop;
	trax_source_write write;
	trax_source_dm_readreg dm_readreg;
	trax_source_dm_writereg dm_writereg;
};

/**
 * Initialize Real-Time Transfer (TRAX).
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_init(void);

/**
 * Shutdown Real-Time Transfer (TRAX).
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_exit(void);

/**
 * Register an TRAX source for a target.
 *
 * @param[in] source TRAX source.
 * @param[in,out] target.
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_register_source(const struct trax_source source,
		struct target *target);

/**
 * Setup TRAX.
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_setup(void);

/**
 * Start Real-Time Transfer (TRAX).
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_start(void);

/**
 * Stop Real-Time Transfer (TRAX).
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_stop(void);

/**
 * Get whether TRAX is started.
 *
 * @returns Whether TRAX is started.
 */
bool trax_started(void);

/**
 * Get whether TRAX is configured.
 *
 * @returns Whether TRAX is configured.
 */
bool trax_configured(void);

/**
 * Register an TRAX sink.
 *
 * @param[in] channel_index Channel index.
 * @param[in,out] user_data User data to be passed to the callback function.
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_register_sink(unsigned int channel_index, void *user_data);

/**
 * Unregister an TRAX sink.
 *
 * @param[in] channel_index Channel index.
 * @param[in,out] user_data User data to be passed to the callback function.
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_unregister_sink(unsigned int channel_index, void *user_data);

/**
 * Write to an TRAX channel.
 *
 * @param[in] channel_index Channel index.
 * @param[in] buffer Data that should be written to the channel.
 * @param[in,out] length Number of bytes to write. On success, the argument gets
 *                       updated with the actual number of written bytes.
 *
 * @returns ERROR_OK on success, an error code on failure.
 */
int trax_write_channel(unsigned int channel_index, const uint8_t *buffer,
		size_t *length);

extern const struct command_registration trax_target_command_handlers[];

#endif /* OPENOCD_TRAX_TRAX_H */
