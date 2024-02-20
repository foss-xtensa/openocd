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

#include <stddef.h>
#include <stdint.h>
#include <helper/log.h>
#include <helper/binarybuffer.h>
#include <helper/command.h>
#include <trax/trax.h>
#include <target/target.h>
#include <target/trax.h>
#include <target/xtensa/xtensa.h>


// TODO: dynamic detection
static bool trax_target_xtensa;


static void target_trax_detect_type(struct target *target)
{
	const char *name = target_name(target);
	trax_target_xtensa = (strncmp(name, "xtensa", 6) == 0);
	LOG_DEBUG("trax target name: %s (%s)", name,
		trax_target_xtensa ? "Found Xtensa" : "Not Found");
}

static int read_trax_channel(struct target *target, unsigned int channel_index,
		enum trax_channel_type type, struct trax_channel *channel)
{
	channel->address = 0;
	channel->name_addr = 0;
	channel->buffer_addr = 0;
	channel->size = TRAX_CHANNEL_BUFFER_MIN_SIZE;
	channel->write_pos = 0;
	channel->read_pos = 0;
	channel->flags = 0;
	LOG_DEBUG("trax target stub: read channel");

	return ERROR_OK;
}

int target_trax_start(struct target *target, void *user_data)
{
	return ERROR_OK;
}

int target_trax_stop(struct target *target, void *user_data)
{
	return ERROR_OK;
}

static int write_to_channel(struct target *target,
		const struct trax_channel *channel, const uint8_t *buffer,
		size_t *length)
{
	LOG_DEBUG("trax target stub: write to channel");
	return ERROR_OK;
}

int target_trax_write_callback(struct target *target, unsigned int channel_index,
		const uint8_t *buffer, size_t *length, void *user_data)
{
	int ret;
	struct trax_channel channel;

	LOG_DEBUG("trax: write callback");
	ret = read_trax_channel(target, channel_index, TRAX_CHANNEL_TYPE_DOWN, &channel);

	if (ret != ERROR_OK) {
		LOG_ERROR("trax: Failed to read down-channel %u description",
			channel_index);
		return ret;
	}

	ret = write_to_channel(target, &channel, buffer, length);

	if (ret != ERROR_OK)
		return ret;

	LOG_DEBUG("trax: Wrote %zu bytes into down-channel %u", *length,
		channel_index);

	return ERROR_OK;
}

int target_trax_attach(struct target *target, bool *found, bool *is_xtensa)
{
	int ret;
	target_trax_detect_type(target);
	if (trax_target_xtensa) {
		struct xtensa *xtensa = target_to_xtensa(target);
		if (!xtensa) {
			LOG_ERROR("trax: attach: NULL target");
			return -1;
		}
		if (xtensa_dm_device_id_read(&xtensa->dbg_mod) != ERROR_OK) {
			LOG_ERROR("trax: attach: device ID read failed");
			return -2;
		}
		xtensa_ocdid_t devid = xtensa_dm_device_id_get(&xtensa->dbg_mod);
		LOG_INFO("trax: xtensa devid is 0x%x", devid);

		if (found)
			*found = (((devid >> TRAX_ID_PRODNO_SHIFT) & TRAX_ID_PRODNO_MASK) == TRAX_ID_PRODNO_TRAX_XTENSA);
		ret = ERROR_OK;
	} else {
		LOG_ERROR("Unsupported TRAX target");
		ret = ERROR_FAIL;
	}
	if (ret == ERROR_OK && is_xtensa)
		*is_xtensa = trax_target_xtensa;
	return ret;
}

int target_trax_dm_readreg(struct target *target, uint32_t regno, uint32_t *value)
{
	if (trax_target_xtensa) {
		struct xtensa *xtensa = target_to_xtensa(target);
		if (!xtensa) {
			LOG_ERROR("trax reg read: NULL target");
			return -1;
		}

		enum xtensa_dm_reg regid = xtensa_dm_regaddr_to_id(regno);
		if (regid == XDMREG_NUM) {
			LOG_ERROR("trax reg read: invalid regno 0x%x", regno);
			return -1;
		}

		uint8_t buf[4];
		int rc = xtensa_dm_queue_reg_read(&xtensa->dbg_mod, regid, buf);
		if (rc != ERROR_OK) {
			LOG_ERROR("trax reg read: xtensa_dm_queue_reg_read error %d", rc);
			return -1;
		}
		xtensa_dm_queue_tdi_idle(&xtensa->dbg_mod);	// TODO: is this required?
		rc = xtensa_dm_queue_execute(&xtensa->dbg_mod);
		if (rc != ERROR_OK) {
			LOG_ERROR("trax reg read: xtensa_dm_queue_execute error %d", rc);
			return -1;
		}
		if (value)
			*value = buf_get_u32(buf, 0, 32);
	} else {
		LOG_ERROR("Unsupported TRAX target");
		return ERROR_FAIL;
	}
	if (value)
		LOG_DEBUG("trax reg read: reg 0x%x val 0x%08x", regno, *value);
	return ERROR_OK;
}

int target_trax_dm_writereg(struct target *target, uint32_t regno, uint32_t value)
{
	if (trax_target_xtensa) {
		struct xtensa *xtensa = target_to_xtensa(target);
		if (!xtensa) {
			LOG_ERROR("trax reg write: NULL target");
			return -1;
		}

		enum xtensa_dm_reg regid = xtensa_dm_regaddr_to_id(regno);
		if (regid == XDMREG_NUM) {
			LOG_ERROR("trax reg write: invalid regno 0x%x", regno);
			return -1;
		}

		int rc = xtensa_dm_queue_reg_write(&xtensa->dbg_mod, regid, value);
		if (rc != ERROR_OK) {
			LOG_ERROR("trax reg write: xtensa_dm_queue_reg_write error %d", rc);
			return -1;
		}
		xtensa_dm_queue_tdi_idle(&xtensa->dbg_mod);	// TODO: is this required?
		rc = xtensa_dm_queue_execute(&xtensa->dbg_mod);
		if (rc != ERROR_OK) {
			LOG_ERROR("trax reg write: xtensa_dm_queue_execute error %d", rc);
			return -1;
		}
	} else {
		LOG_ERROR("Unsupported TRAX target");
		return ERROR_FAIL;
	}
	LOG_DEBUG("trax reg write: reg 0x%x val 0x%08x", regno, value);
	return ERROR_OK;
}

