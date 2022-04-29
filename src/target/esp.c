/***************************************************************************
 *   Espressif chips common target API for OpenOCD                         *
 *   Copyright (C) 2021 Espressif Systems Ltd.                             *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#include <helper/log.h>
#include <helper/binarybuffer.h>
#include "target.h"
#include "esp.h"

#define ESP_FLASH_BREAKPOINTS_MAX_NUM  32

int esp_common_handle_gdb_detach(struct target *target)
{
	int ret;

	enum target_state old_state = target->state;
	if (target->state != TARGET_HALTED) {
		ret = target_halt(target);
		if (ret != ERROR_OK) {
			LOG_TARGET_ERROR(
				target,
				"Failed to halt target to remove flash BPs (%d)!",
				ret);
			return ret;
		}
		ret = target_wait_state(target, TARGET_HALTED, 3000);
		if (ret != ERROR_OK) {
			LOG_TARGET_ERROR(
				target,
				"Failed to wait halted target to remove flash BPs (%d)!",
				ret);
			return ret;
		}
	}
	if (old_state == TARGET_RUNNING) {
		ret = target_resume(target, 1, 0, 1, 0);
		if (ret != ERROR_OK) {
			LOG_TARGET_ERROR(
				target,
				"Failed to resume target after flash BPs removal (%d)!",
				ret);
			return ret;
		}
	}
	return ERROR_OK;
}
