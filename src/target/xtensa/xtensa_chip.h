/***************************************************************************
 *   Xtensa Chip-level Target Support for OpenOCD                          *
 *   Copyright (C) 2020-2022 Cadence Design Systems, Inc.                  *
 *   Author: Ian Thompson <ianst@cadence.com>                              *
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
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifndef OPENOCD_TARGET_XTENSA_CHIP_H
#define OPENOCD_TARGET_XTENSA_CHIP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <target/target.h>
#include "xtensa.h"
#include "xtensa_debug_module.h"

/* 0 - don't care, 1 - TMS low, 2 - TMS high */
enum flash_bootstrap {
	FBS_DONTCARE = 0,
	FBS_TMSLOW,
	FBS_TMSHIGH,
};

struct xtensa_chip_common {
	struct xtensa xtensa;

	/* TODO: remove following fields
	 * struct TBD_dbg_stubs dbg_stubs;
	 */
	enum flash_bootstrap flash_bootstrap;
};

static inline struct xtensa_chip_common *target_to_xtensa_chip(struct target *target)
{
	return container_of(target->arch_info, struct xtensa_chip_common, xtensa);
}


int xtensa_chip_init_arch_info(struct target *target, void *arch_info, 
		struct xtensa_debug_module_config *dm_cfg);
int xtensa_chip_target_init(struct command_context *cmd_ctx, struct target *target);
int xtensa_chip_arch_state(struct target *target);
void xtensa_chip_queue_tdi_idle(struct target *target);
void xtensa_chip_on_reset(struct target *target);
bool xtensa_chip_on_halt(struct target *target);
void xtensa_chip_on_poll(struct target *target);

#endif	/* OPENOCD_TARGET_XTENSA_CHIP_H */
