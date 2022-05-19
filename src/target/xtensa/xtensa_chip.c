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
#include "xtensa_fileio.h"


int xtensa_chip_init_arch_info(struct target *target, void *arch_info, 
		struct xtensa_debug_module_config *dm_cfg)
{
	struct xtensa_chip_common *xtensa_chip = (struct xtensa_chip_common *)arch_info;

#if 0   /* TODO: required? */
	int ret = target_register_exit_callback(xtensa_chip_on_exit, NULL);
	if (ret != ERROR_OK)
		return ret;
	ret = target_register_event_callback(xtensa_chip_handle_target_event, target);
	if (ret != ERROR_OK)
		return ret;
#else
	int ret;
#endif  /* TODO: required? */

	if ((dm_cfg->queue_tdi_idle == NULL) && (dm_cfg->tap != NULL)) {
		dm_cfg->queue_tdi_idle = xtensa_chip_queue_tdi_idle;
		dm_cfg->queue_tdi_idle_arg = target;
	}
	ret = xtensa_init_arch_info(target, &xtensa_chip->xtensa, dm_cfg);
	if (ret != ERROR_OK) {
		return ret;
	}
	/* All xtensa target structures point back to original xtensa_chip */
	xtensa_chip->xtensa.xtensa_chip = arch_info;
	return ERROR_OK;
}

static int xtensa_chip_handle_target_event(struct target *target, enum target_event event, void *priv)
{
    if (target != priv)
        return ERROR_OK;

    LOG_DEBUG("%d", event);

    int ret = xtensa_handle_target_event(target, event, priv);
    if (ret != ERROR_OK)
        return ret;

    switch (event) {
        case TARGET_EVENT_HALTED:
            /* debug stubs not supported */
            break;
        case TARGET_EVENT_GDB_DETACH:
            /* Flash BP not supported */
            break;
        default:
            break;
    }
    return ERROR_OK;
}

int xtensa_chip_target_init(struct command_context *cmd_ctx, struct target *target)
{
    int ret = xtensa_target_init(cmd_ctx, target);
    if (ret != ERROR_OK)
        return ret;

    ret = target_register_event_callback(xtensa_chip_handle_target_event, target);
    if (ret != ERROR_OK)
        return ret;

    ret = xtensa_fileio_init(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
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
            xtensa_fileio_detect_proc(target);
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
	struct xtensa *xtensa = target_to_xtensa(target);
	struct xtensa_chip_common *xtensa_chip = xtensa->xtensa_chip;
	static uint8_t value;
	uint8_t t[4] = { 0, 0, 0, 0 };

	if (xtensa_chip->flash_bootstrap == FBS_TMSLOW) {
		/*Make sure tdi is 0 at the exit of queue execution */
		value = 0;
	} else if (xtensa_chip->flash_bootstrap == FBS_TMSHIGH) {
		/*Make sure tdi is 1 at the exit of queue execution */
		value = 1;
	} else
		return;

	/*Scan out 1 bit, do not move from IRPAUSE after we're done. */
	buf_set_u32(t, 0, 1, value);
	jtag_add_plain_ir_scan(1, t, NULL, TAP_IRPAUSE);
}

static int xtensa_chip_virt2phys(struct target *target,
	target_addr_t virtual, target_addr_t *physical)
{
	*physical = virtual;
	return ERROR_OK;
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
		.dap = NULL,
		.debug_ap = NULL,
		.debug_apsel = DP_APSEL_INVALID,
		.ap_offset = 0,
	};

	struct adiv5_private_config *pc;
	pc = (struct adiv5_private_config *)target->private_config;
	if (adiv5_verify_config(pc) == ERROR_OK) {
		xtensa_chip_dm_cfg.dap = pc->dap;
		xtensa_chip_dm_cfg.debug_apsel = pc->ap_num;
		LOG_DEBUG("DAP: ap_num %d DAP %p", pc->ap_num, pc->dap);
	} else {
		xtensa_chip_dm_cfg.tap = target->tap;
		LOG_DEBUG("JTAG: %s:%s pos %d", target->tap->chip, target->tap->tapname, target->tap->abs_chain_position);
	}

	struct xtensa_chip_common *xtensa_chip = calloc(1, sizeof(struct xtensa_chip_common));
	if (xtensa_chip == NULL) {
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

static int xtensa_chip_examine(struct target *target)
{
	struct xtensa *xtensa = target_to_xtensa(target);
	int retval = xtensa_dm_examine(&xtensa->dbg_mod);
	if (retval == ERROR_OK) {
		retval = xtensa_examine(target);
	}
	return retval;
}

int xtensa_chip_jim_configure(struct target *target, struct jim_getopt_info *goi)
{
	static bool dap_configured = false;
	int ret = adiv5_jim_configure(target, goi);
	if (ret == JIM_OK) {
		LOG_DEBUG("xtensa '-dap' target option found");
		dap_configured = true;
	}
	if (!dap_configured) {
		LOG_DEBUG("xtensa '-dap' target option not yet found, assuming JTAG...");
		target->has_dap = false;
	}
	return ret;
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

	.gdb_query_custom = xtensa_gdb_query_custom,

	.commands = xtensa_command_handlers,

	.get_gdb_fileio_info = xtensa_get_gdb_fileio_info,
	.gdb_fileio_end = xtensa_gdb_fileio_end,
};
