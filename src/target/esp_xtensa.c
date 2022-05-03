/***************************************************************************
 *   Espressif Xtensa target API for OpenOCD                               *
 *   Copyright (C) 2019 Espressif Systems Ltd.                             *
 *   Author: Alexey Gerenkov <alexey@espressif.com>                        *
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

#include <stdbool.h>
#include <stdint.h>
#include "smp.h"
#include "esp_xtensa.h"
#include "register.h"

int esp_xtensa_handle_target_event(struct target *target, enum target_event event,
	void *priv)
{
	int ret;

	if (target != priv)
		return ERROR_OK;

	LOG_DEBUG("%d", event);

	ret = xtensa_handle_target_event(target, event, priv);
	if (ret != ERROR_OK)
		return ret;

	switch (event) {
		case TARGET_EVENT_HALTED:
			break;
		case TARGET_EVENT_GDB_DETACH:
		{
			ret = esp_common_handle_gdb_detach(target);
			if (ret != ERROR_OK)
				return ret;
			break;
		}
		default:
			break;
	}
	return ERROR_OK;
}

int esp_xtensa_init_arch_info(struct target *target,
	struct esp_xtensa_common *esp_xtensa,
	struct xtensa_debug_module_config *dm_cfg)
{
	int ret = xtensa_init_arch_info(target, &esp_xtensa->xtensa, dm_cfg);
	if (ret != ERROR_OK)
		return ret;
	return ERROR_OK;
}

int esp_xtensa_target_init(struct command_context *cmd_ctx, struct target *target)
{
	return xtensa_target_init(cmd_ctx, target);
}

void esp_xtensa_target_deinit(struct target *target)
{
	LOG_DEBUG("start");

	xtensa_target_deinit(target);
}

int esp_xtensa_arch_state(struct target *target)
{
	return ERROR_OK;
}

int esp_xtensa_poll(struct target *target)
{
	return xtensa_poll(target);
}

int esp_xtensa_breakpoint_add(struct target *target, struct breakpoint *breakpoint)
{
	return xtensa_breakpoint_add(target, breakpoint);
	/* flash breakpoints will be handled in another patch */
}

int esp_xtensa_breakpoint_remove(struct target *target, struct breakpoint *breakpoint)
{
	return xtensa_breakpoint_remove(target, breakpoint);
	/* flash breakpoints will be handled in another patch */
}
