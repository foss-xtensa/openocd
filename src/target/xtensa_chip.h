/***************************************************************************
 *   Xtensa Chip-level Target Support for OpenOCD                          *
 *   Copyright (C) 2020-2021 Cadence Design Systems, Inc.                  *
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

#ifndef XTENSA_CHIP_H
#define XTENSA_CHIP_H

#include "target.h"
#include "command.h"
#include "xtensa.h"
#include "xtensa_debug_module.h"

#if 0 

/**
 * Debug stubs table entries IDs
 *
 * @note Must be in sync with TBD-IDF version
 */
enum TBD_dbg_stub_id {
	TBD_DBG_STUB_TABLE_START,
	TBD_DBG_STUB_DESC = TBD_DBG_STUB_TABLE_START,	/*< Stubs descriptor ID */
	TBD_DBG_STUB_ENTRY_FIRST,
	TBD_DBG_STUB_ENTRY_GCOV = TBD_DBG_STUB_ENTRY_FIRST,	/*< GCOV stub ID */
	/* add new stub entries here */
	TBD_DBG_STUB_ENTRY_MAX,
};

/**
 * Debug stubs descriptor. ID: TBD_DBG_STUB_DESC
 *
 * @note Must be in sync with TBD-IDF version
 */
struct TBD_dbg_stubs_desc {
	/** Address of pre-compiled target buffer for stub trampoline. The size of buffer the is
	 * TBD_DBG_STUBS_CODE_BUF_SIZE. */
	uint32_t tramp_addr;
	/** Pre-compiled target buffer's addr for stack. The size of the buffer is TBD_DBG_STUBS_STACK_MIN_SIZE.
	    Target has the buffer which is used for the stack of onboard algorithms.
	If stack size required by algorithm exceeds TBD_DBG_STUBS_STACK_MIN_SIZE,
	it should be allocated using onboard function pointed by 'data_alloc' and
	freed by 'data_free'. They fit to the minimal stack. See below. */
	uint32_t min_stack_addr;
	/** Address of malloc-like function to allocate buffer on target. */
	uint32_t data_alloc;
	/** Address of free-like function to free buffer allocated with data_alloc. */
	uint32_t data_free;
};

/**
 * Debug stubs info.
 */
struct TBD_dbg_stubs {
	/** Address. */
	uint32_t base;
	/** Table contents. */
	uint32_t entries[TBD_DBG_STUB_ENTRY_MAX];
	/** Number of table entries. */
	uint32_t entries_count;
	/** Debug stubs decsriptor. */
	struct TBD_dbg_stubs_desc desc;
};

#endif

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

#endif	/* XTENSA_CHIP_H */
