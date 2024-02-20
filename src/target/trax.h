/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Copyright (C) 2016-2020 by Marc Schink <dev@zapb.de>
 * Copyright (C) 2023 by Cadence Design Systems, Inc.
 *
 * Based on RTT server.
 */

#ifndef OPENOCD_TARGET_TRAX_H
#define OPENOCD_TARGET_TRAX_H

#include <stdint.h>
#include <stdbool.h>

#include <target/target.h>
#include <trax/trax.h>

int target_trax_start(struct target *target, void *user_data);
int target_trax_stop(struct target *target, void *user_data);
int target_trax_attach(struct target *target, bool *found, bool *is_xtensa);
int target_trax_write_callback(struct target *target, unsigned int channel_index,
		const uint8_t *buffer, size_t *length, void *user_data);
int target_trax_dm_readreg(struct target *target, uint32_t regno, uint32_t *value);
int target_trax_dm_writereg(struct target *target, uint32_t regno, uint32_t value);

#endif /* OPENOCD_TARGET_TRAX_H */
