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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "assert.h"
#include <target/target.h>
#include <target/target_type.h>
#include <target/arm_adi_v5.h>
#include <rtos/rtos.h>
#include "xtensa_chip.h"


int xtensa_chip_init_arch_info(struct target *target, void *arch_info, 
		struct xtensa_debug_module_config *dm_cfg)
{
	struct xtensa_chip_common *xtensa_chip = (struct xtensa_chip_common *)arch_info;
	if (!dm_cfg->queue_tdi_idle && dm_cfg->tap) {
		dm_cfg->queue_tdi_idle = xtensa_chip_queue_tdi_idle;
		dm_cfg->queue_tdi_idle_arg = target;
	}
	int ret = xtensa_init_arch_info(target, &xtensa_chip->xtensa, dm_cfg);
	if (ret != ERROR_OK) {
		return ret;
	}
	/* All xtensa target structures point back to original xtensa_chip */
	xtensa_chip->xtensa.xtensa_chip = arch_info;
	return ERROR_OK;
}

int xtensa_chip_target_init(struct command_context *cmd_ctx, struct target *target)
{
	return xtensa_target_init(cmd_ctx, target);
}

int xtensa_chip_arch_state(struct target *target)
{
	return ERROR_OK;
}

static int xtensa_chip_poll(struct target *target)
{
	enum target_state old_state = target->state;
	int ret;

	ret = xtensa_poll(target);

	if (old_state != TARGET_HALTED && target->state == TARGET_HALTED) {
		/*Call any event callbacks that are applicable */
		if (old_state == TARGET_DEBUG_RUNNING)
			target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
		else {
			target_call_event_callbacks(target, TARGET_EVENT_HALTED);
		}
	}

	return ret;
}

/* 
 * TODO: Remove if possible
 *
The TDI pin is also used as a flash Vcc bootstrap pin. If we reset the CPU externally, the last state of the TDI pin can
allow the power to an 1.8V flash chip to be raised to 3.3V, or the other way around. 
*/
void xtensa_chip_queue_tdi_idle(struct target *target)
{
	static uint32_t value = 0;
	uint8_t t[4] = { 0, 0, 0, 0 };

#if 0
	struct xtensa *xtensa = target_to_xtensa(target);
	struct xtensa_chip_common *xtensa_chip = xtensa->xtensa_chip;
	if (xtensa_chip->flash_bootstrap == FBS_TMSLOW) {
		/*Make sure tdi is 0 at the exit of queue execution */
		value = 0;
	} else if (xtensa_chip->flash_bootstrap == FBS_TMSHIGH) {
		/*Make sure tdi is 1 at the exit of queue execution */
		value = 1;
	} else
		return;
#endif

	/* Scan out 1 bit, do not move from IRPAUSE after we're done. */
	buf_set_u32(t, 0, 1, value);
	jtag_add_plain_ir_scan(1, t, NULL, TAP_IRPAUSE);
}

static int xtensa_chip_virt2phys(struct target *target,
	target_addr_t virtual, target_addr_t *physical)
{
	if (physical) {
		*physical = virtual;
		return ERROR_OK;
	}
	return ERROR_FAIL;
}

static const struct xtensa_debug_ops xtensa_chip_dm_dbg_ops = {
	.queue_enable = xtensa_dm_queue_enable,
	.queue_reg_read = xtensa_dm_queue_reg_read,
	.queue_reg_write = xtensa_dm_queue_reg_write
};

static const struct xtensa_power_ops xtensa_chip_dm_pwr_ops = {
	.queue_reg_read = xtensa_dm_queue_pwr_reg_read,
	.queue_reg_write = xtensa_dm_queue_pwr_reg_write
};

static int xtensa_chip_target_create(struct target *target, Jim_Interp *interp)
{
	struct xtensa_debug_module_config xtensa_chip_dm_cfg = {
		.dbg_ops = &xtensa_chip_dm_dbg_ops,
		.pwr_ops = &xtensa_chip_dm_pwr_ops,
		.tap = NULL,
		.queue_tdi_idle = NULL,
		.queue_tdi_idle_arg = NULL,
	};

	xtensa_chip_dm_cfg.tap = target->tap;
	LOG_DEBUG("JTAG: %s:%s pos %d", target->tap->chip, target->tap->tapname, target->tap->abs_chain_position);

	struct xtensa_chip_common *xtensa_chip = calloc(1, sizeof(struct xtensa_chip_common));
	if (!xtensa_chip) {
		LOG_ERROR("Failed to alloc chip-level memory!");
		return ERROR_FAIL;
	}

	int ret = xtensa_chip_init_arch_info(target, xtensa_chip, &xtensa_chip_dm_cfg);
	if (ret != ERROR_OK) {
		LOG_ERROR("Failed to init arch info!");
		free(xtensa_chip);
		return ret;
	}

	/*Assume running target. If different, the first poll will fix this. */
	target->state = TARGET_RUNNING;
	target->debug_reason = DBG_REASON_NOTHALTED;
	return ERROR_OK;
}


void xtensa_chip_target_deinit(struct target *target)
{
	struct xtensa *xtensa = target_to_xtensa(target);
	xtensa_target_deinit(target);
	free(xtensa->xtensa_chip);
}

static int xtensa_chip_examine(struct target *target)
{
	return xtensa_examine(target);
}

int xtensa_chip_jim_configure(struct target *target, struct jim_getopt_info *goi)
{
	target->has_dap = false;
	return JIM_CONTINUE;
}

/** Methods for generic example of Xtensa-based chip-level targets. */
struct target_type xtensa_chip_target = {
	.name = "xtensa",

	.poll = xtensa_chip_poll,
	.arch_state = xtensa_chip_arch_state,

	.halt = xtensa_halt,
	.resume = xtensa_resume,
	.step = xtensa_step,

	.assert_reset = xtensa_assert_reset,
	.deassert_reset = xtensa_deassert_reset,
	.soft_reset_halt = xtensa_soft_reset_halt,

	.virt2phys = xtensa_chip_virt2phys,
	.mmu = xtensa_mmu_is_enabled,
	.read_memory = xtensa_read_memory,
	.write_memory = xtensa_write_memory,

	.read_buffer = xtensa_read_buffer,
	.write_buffer = xtensa_write_buffer,

	.checksum_memory = xtensa_checksum_memory,

	.get_gdb_reg_list = xtensa_get_gdb_reg_list,

	.add_breakpoint = xtensa_breakpoint_add,
	.remove_breakpoint = xtensa_breakpoint_remove,

	.add_watchpoint = xtensa_watchpoint_add,
	.remove_watchpoint = xtensa_watchpoint_remove,

	.target_create = xtensa_chip_target_create,
	.target_jim_configure = xtensa_chip_jim_configure,
	.init_target = xtensa_chip_target_init,
	.examine = xtensa_chip_examine,
	.deinit_target = xtensa_chip_target_deinit,

	.gdb_query_custom = xtensa_gdb_query_custom,

	.commands = xtensa_command_handlers,
};
