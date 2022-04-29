/***************************************************************************
 *   Xtensa Target Support for OpenOCD                                     *
 *   Copyright (C) 2020-2022 Cadence Design Systems, Inc.                  *
 *   Author: Ian Thompson <ianst@cadence.com>                              *
 *                                                                         *
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

#ifndef OPENOCD_TARGET_XTENSA_H
#define OPENOCD_TARGET_XTENSA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "target.h"
#include "assert.h"
#include "breakpoints.h"
#include "xtensa_chip.h"
#include "xtensa_regs.h"
#include "xtensa_debug_module.h"

#include "helper/types.h"

/**
 * @file
 * Holds the interface to Xtensa cores.
 */

/* Big-endian vs. little-endian detection */
#define isbe(X)		((X)->core_config->bigendian)

/* Swap 4-bit Xtensa opcodes and fields */
#define nibswap8(V)									\
		( (((V) & 0x0F) << 4)						\
		| (((V) & 0xF0) >> 4) )

#define nibswap16(V)								\
		( (((V) & 0x000F) << 12)					\
		| (((V) & 0x00F0) << 4)						\
		| (((V) & 0x0F00) >> 4)						\
		| (((V) & 0xF000) >> 12) )

#define nibswap24(V)								\
		( (((V) & 0x00000F) << 20)					\
		| (((V) & 0x0000F0) << 12)					\
		| (((V) & 0x000F00) << 4)					\
		| (((V) & 0x00F000) >> 4)					\
		| (((V) & 0x0F0000) >> 12)					\
		| (((V) & 0xF00000) >> 20) )

/* _XT_INS_FORMAT_*()
 * Instruction formatting converted from little-endian inputs
 * and shifted to the MSB-side of DIR for BE systems.
 */
#define _XT_INS_FORMAT_RSR(X,OPCODE,SR,T)			\
		(isbe(X) ? (nibswap24(OPCODE)				\
		 | (((T) & 0x0F) << 16)						\
		 | (((SR) & 0xFF) << 8)) << 8				\
		: (OPCODE)									\
		 | (((SR) & 0xFF) << 8)						\
		 | (((T) & 0x0F) << 4))

#define _XT_INS_FORMAT_RRR(X,OPCODE,ST,R)			\
		(isbe(X) ? (nibswap24(OPCODE)				\
		 | ((nibswap8((ST) & 0xFF)) << 12)			\
		 | (((R) & 0x0F) << 8)) << 8				\
		: (OPCODE)									\
		 | (((ST) & 0xFF) << 4)						\
		 | (((R) & 0x0F) << 12))

#define _XT_INS_FORMAT_RRRN(X,OPCODE,S, T,IMM4)		\
		(isbe(X) ? (nibswap16(OPCODE)				\
		 | (((T) & 0x0F) << 8)						\
		 | (((S) & 0x0F) << 4)						\
		 | ((IMM4) & 0x0F)) << 16					\
		: (OPCODE)									\
		 | (((T) & 0x0F) << 4)						\
		 | (((S) & 0x0F) << 8)						\
		 | (((IMM4) & 0x0F) << 12))

#define _XT_INS_FORMAT_RRI8(X,OPCODE,R,S,T,IMM8)	\
		(isbe(X) ? (nibswap24(OPCODE)				\
		 | (((T) & 0x0F) << 16)						\
		 | (((S) & 0x0F) << 12)						\
		 | (((R) & 0x0F) << 8)						\
		 | ((IMM8) & 0xFF)) << 8					\
		: (OPCODE)									\
		 | (((IMM8) & 0xFF) << 16)					\
		 | (((R) & 0x0F) << 12)						\
		 | (((S) & 0x0F) << 8)						\
		 | (((T) & 0x0F) << 4))

#define _XT_INS_FORMAT_RRI4(X,OPCODE,IMM4,R,S,T)	\
		(isbe(X) ? (nibswap24(OPCODE)				\
		 | (((T) & 0x0F) << 16)						\
		 | (((S) & 0x0F) << 12)						\
		 | (((R) & 0x0F) << 8)) << 8				\
		 | ((IMM4) & 0x0F)							\
		: (OPCODE)									\
		 | (((IMM4) & 0x0F) << 20)					\
		 | (((R) & 0x0F) << 12)						\
		 | (((S) & 0x0F) << 8)						\
		 | (((T) & 0x0F) << 4))


/* Xtensa processor instruction opcodes
*/
/* "Return From Debug Operation" to Normal */
#define XT_INS_RFDO(X) (isbe(X) ? 0x000e1f << 8 : 0xf1e000)
/* "Return From Debug and Dispatch" - allow sw debugging stuff to take over */
#define XT_INS_RFDD(X) (isbe(X) ? 0x010e1f << 8 : 0xf1e010)

/* Load to DDR register, increase addr register */
#define XT_INS_LDDR32P(X,S) (isbe(X) ? (0x0E0700|((S)<<12)) << 8 : (0x0070E0|((S)<<8)))
/* Store from DDR register, increase addr register */
#define XT_INS_SDDR32P(X,S) (isbe(X) ? (0x0F0700|((S)<<12)) << 8 : (0x0070F0|((S)<<8)))

/* Load 32-bit Indirect from A(S)+4*IMM8 to A(T) */
#define XT_INS_L32I(X,S,T,IMM8)  _XT_INS_FORMAT_RRI8(X,0x002002,0,S,T,IMM8)
/* Load 16-bit Unsigned from A(S)+2*IMM8 to A(T) */
#define XT_INS_L16UI(X,S,T,IMM8) _XT_INS_FORMAT_RRI8(X,0x001002,0,S,T,IMM8)
/* Load 8-bit Unsigned from A(S)+IMM8 to A(T) */
#define XT_INS_L8UI(X,S,T,IMM8)  _XT_INS_FORMAT_RRI8(X,0x000002,0,S,T,IMM8)

/* Store 32-bit Indirect to A(S)+4*IMM8 from A(T) */
#define XT_INS_S32I(X,S,T,IMM8) _XT_INS_FORMAT_RRI8(X,0x006002,0,S,T,IMM8)
/* Store 16-bit to A(S)+2*IMM8 from A(T) */
#define XT_INS_S16I(X,S,T,IMM8) _XT_INS_FORMAT_RRI8(X,0x005002,0,S,T,IMM8)
/* Store 8-bit to A(S)+IMM8 from A(T) */
#define XT_INS_S8I(X,S,T,IMM8)  _XT_INS_FORMAT_RRI8(X,0x004002,0,S,T,IMM8)

/* Cache Instructions */
#define XT_INS_IHI(X,S,IMM8) _XT_INS_FORMAT_RRI8(X,0x0070E2,0,S,0,IMM8)
#define XT_INS_DHWBI(X,S,IMM8) _XT_INS_FORMAT_RRI8(X,0x007052,0,S,0,IMM8)
#define XT_INS_DHWB(X,S,IMM8) _XT_INS_FORMAT_RRI8(X,0x007042,0,S,0,IMM8)
#define XT_INS_ISYNC(X) (isbe(X) ? 0x000200 << 8 : 0x002000)

/* Control Instructions */
#define XT_INS_JX(X,S) (isbe(X) ? (0x050000|((S)<<12)) : (0x0000a0|((S)<<8)))
#define XT_INS_CALL0(X,IMM18) (isbe(X) ? (0x500000|((IMM18)&0x3ffff)) : (0x000005|(((IMM18)&0x3ffff)<<6)))

/* Read Special Register */
#define XT_INS_RSR(X,SR,T) _XT_INS_FORMAT_RSR(X,0x030000,SR,T)
/* Write Special Register */
#define XT_INS_WSR(X,SR,T) _XT_INS_FORMAT_RSR(X,0x130000,SR,T)
/* Swap Special Register */
#define XT_INS_XSR(X,SR,T) _XT_INS_FORMAT_RSR(X,0x610000,SR,T)

/* Rotate Window by (-8..7) */
#define XT_INS_ROTW(X,N) (isbe(X) ? ((0x000804)|(((N)&15)<<16)) << 8 : ((0x408000)|(((N)&15)<<4)))

/* Read User Register */
#define XT_INS_RUR(X,UR,T) _XT_INS_FORMAT_RRR(X,0xE30000,UR,T)
/* Write User Register */
#define XT_INS_WUR(X,UR,T) _XT_INS_FORMAT_RSR(X,0xF30000,UR,T)

/* 24-bit break; BE version field-swapped then byte-swapped for use in memory R/W fns */
#define XT_INS_BREAK(X,S,T)	(isbe(X) ?                         \
				(0x000400 | (((S)&0xF)<<12) | ((T)&0xF)) :     \
				(0x004000 | (((S)&0xF)<<8)  | (((T)&0xF)<<4)))
/* 16-bit break; BE version field-swapped then byte-swapped for use in memory R/W fns */
#define XT_INS_BREAKN(X,IMM4) (isbe(X) ?        \
				(0x0FD2 | (((IMM4)&0xF)<<12)) : \
				(0xF02D | (((IMM4)&0xF)<<8)))

/* PS register bits (LX) */
#define XT_PS_RING(_v_)         ((uint32_t)((_v_) & 0x3) << 6)
#define XT_PS_RING_MSK          (0x3 << 6)
#define XT_PS_RING_GET(_v_)     (((_v_) >> 6) & 0x3)
#define XT_PS_CALLINC_MSK       (0x3 << 16)
#define XT_PS_OWB_MSK           (0xF << 8)
#define XT_PS_WOE_MSK           (1 << 18)

/* PS register bits (NX) */
#define XT_PS_DIEXC_MSK         (1 << 2)

/* MS register bits (NX) */
#define XT_MS_DE_MSK            (1 << 5)
#define XT_MS_DISPST_MSK        (0x1f)
#define XT_MS_DISPST_DBG        (0x10)

/* WB register bits (NX) */
#define XT_WB_P_SHIFT           (0)
#define XT_WB_P_MSK             (0x7 << XT_WB_P_SHIFT)
#define XT_WB_C_SHIFT           (4)
#define XT_WB_C_MSK             (0x7 << XT_WB_C_SHIFT)
#define XT_WB_N_SHIFT           (8)
#define XT_WB_N_MSK             (0x7 << XT_WB_N_SHIFT)
#define XT_WB_S_SHIFT           (30)
#define XT_WB_S_MSK             (0x3 << XT_WB_S_SHIFT)

/* IBREAKC register bits (NX) */
#define XT_IBREAKC_FB           (0x80000000)

/* Definitions for imprecise exception registers (NX) */
#define XT_IMPR_EXC_MSK         (0x00000013)
#define XT_MESRCLR_IMPR_EXC_MSK (0x00000090)

#define XT_INS_L32E(X,R,S,T) _XT_INS_FORMAT_RRI4(X,0x090000,0,R,S,T)
#define XT_INS_S32E(X,R,S,T) _XT_INS_FORMAT_RRI4(X,0x490000,0,R,S,T)
#define XT_INS_L32E_S32E_MASK(X)   (isbe(X) ? 0xF000FF << 8 : 0xFF000F)

#define XT_INS_RFWO(X) (isbe(X) ? 0x004300 << 8 : 0x003400)
#define XT_INS_RFWU(X) (isbe(X) ? 0x005300 << 8 : 0x003500)
#define XT_INS_RFWO_RFWU_MASK(X)   (isbe(X) ? 0xFFFFFF << 8 : 0xFFFFFF)

#define XT_ISNS_SZ_MAX                  3
#define XT_LOCAL_MEM_REGIONS_NUM_MAX    8

#define XT_AREGS_NUM_MAX                64
#define XT_USER_REGS_NUM_MAX            256

#define XT_MEM_ACCESS_NONE              0x0
#define XT_MEM_ACCESS_READ              0x1
#define XT_MEM_ACCESS_WRITE             0x2

enum xtensa_qerr_e {
	XT_QERR_INTERNAL = 0,
	XT_QERR_FAIL,
	XT_QERR_INVAL,
	XT_QERR_MEM,
	XT_QERR_NUM,
};

/* An and ARn registers potentially used as scratch regs */
enum xtensa_ar_scratch_set_e {
	XT_AR_SCRATCH_A3 = 0,
	XT_AR_SCRATCH_AR3,
	XT_AR_SCRATCH_A4,
	XT_AR_SCRATCH_AR4,
	XT_AR_SCRATCH_NUM
};

struct xtensa_keyval_info_s {
	char *chrval;
	int intval;
};

enum xtensa_type {
	XT_UNDEF = 0,
	XT_LX,
	XT_NX,
};

struct xtensa_cache_config {
	uint8_t way_count;
	uint32_t line_size;
	uint32_t size;
	int writeback;
};

struct xtensa_local_mem_region_config {
	uint32_t base;
	uint32_t size;
	int access;
};

struct xtensa_local_mem_config {
	uint16_t count;
	struct xtensa_local_mem_region_config regions[XT_LOCAL_MEM_REGIONS_NUM_MAX];
};

struct xtensa_mmu_config {
	bool enabled;
	uint8_t itlb_entries_count;
	uint8_t dtlb_entries_count;
};

struct xtensa_mpu_config {
	bool enabled;
	uint8_t nfgseg;
	uint32_t minsegsize;
	bool lockable;
	bool execonly;
};

struct xtensa_irq_config {
	bool enabled;
	uint8_t irq_num;
};

struct xtensa_high_prio_irq_config {
	bool enabled;
	uint8_t level_num;
	uint8_t excm_level;
};

struct xtensa_debug_config {
	bool enabled;
	uint8_t irq_level;
	uint8_t ibreaks_num;
	uint8_t dbreaks_num;
};

struct xtensa_tracing_config {
	bool enabled;
	uint32_t mem_sz;
	bool reversed_mem_access;
};

typedef union {
	uint32_t d32;
	uint8_t d8[4];
} xtensa_union32;

struct xtensa_config {
	enum xtensa_type core_type;
	bool bigendian;
	uint8_t aregs_num;
	bool windowed;
	bool coproc;
	bool exceptions;
	struct xtensa_irq_config irq;
	struct xtensa_high_prio_irq_config high_irq;
	struct xtensa_mmu_config mmu;
	struct xtensa_mpu_config mpu;
	struct xtensa_debug_config debug;
	struct xtensa_tracing_config trace;
	struct xtensa_cache_config icache;
	struct xtensa_cache_config dcache;
	struct xtensa_local_mem_config irom;
	struct xtensa_local_mem_config iram;
	struct xtensa_local_mem_config drom;
	struct xtensa_local_mem_config dram;
	struct xtensa_local_mem_config sram;
	struct xtensa_local_mem_config srom;
};

typedef uint32_t xtensa_insn_t;

enum xtensa_stepping_isr_mode {
	XT_STEPPING_ISR_OFF,	/* interrupts are disabled during stepping */
	XT_STEPPING_ISR_ON,		/* interrupts are enabled during stepping */
};

typedef enum xtensa_nx_reg_idx_e {
	XT_NX_REG_IDX_IBREAKC0 = 0,
	XT_NX_REG_IDX_WB,
	XT_NX_REG_IDX_MS,
	XT_NX_REG_IDX_IEVEC,		/* IEVEC, IEEXTERN, and MESR must be contiguous */
	XT_NX_REG_IDX_IEEXTERN,
	XT_NX_REG_IDX_MESR,
	XT_NX_REG_IDX_MESRCLR,
	XT_NX_REG_IDX_NUM
} xtensa_nx_reg_idx;

struct xtensa_sw_breakpoint {
	struct breakpoint *oocd_bp;
	/* original insn */
	uint8_t insn[XT_ISNS_SZ_MAX];
	/* original insn size */
	uint8_t insn_sz;	/* 2 or 3 bytes */
};

/**
 * Represents a generic Xtensa core.
 */
struct xtensa {
	struct xtensa_chip_common *xtensa_chip;
	struct xtensa_config *core_config;
	struct xtensa_debug_module dbg_mod;
	struct reg_cache *core_cache;
	uint32_t total_regs_num;
	uint32_t core_regs_num;
	/* An array of pointers to buffers to backup registers' values while algo is run on target.
	 * Size is 'regs_num'. */
	void **algo_context_backup;
	uint32_t eps_dbglevel_idx;
	uint32_t dbregs_num;
	struct target *target;
	bool reset_asserted;
	enum xtensa_stepping_isr_mode stepping_isr_mode;
	bool resp_gdb_restart_pkt;
	struct breakpoint **hw_brps;
	struct watchpoint **hw_wps;
	struct xtensa_sw_breakpoint *sw_brps;
	bool trace_active;
	bool permissive_mode;
	bool suppress_dsr_errors;
	uint32_t smp_break;
	uint32_t spill_loc;
	uint32_t spill_bytes;
	uint8_t *spill_buf;
	int8_t probe_lsddr32p;
	/* Sometimes debug module's 'powered' bit is cleared after reset, but get set after some
	 * time.This is the number of polling periods after which core is considered to be powered
	 * off (marked as unexamined) if the bit retains to be cleared (e.g. if core is disabled by
	 * SW running on target).*/
	uint8_t come_online_probes_num;
	bool proc_syscall;
	bool halt_request;
	uint32_t nx_stop_cause;
	uint32_t nx_reg_idx[XT_NX_REG_IDX_NUM];
	struct xtensa_keyval_info_s scratch_ars[XT_AR_SCRATCH_NUM];
};

static inline struct xtensa *target_to_xtensa(struct target *target)
{
	assert(target != NULL);
	return target->arch_info;
}

static inline int xtensa_queue_dbg_reg_read(struct xtensa *xtensa, xtensa_dm_reg reg, uint32_t *data)
{
	struct xtensa_debug_module *dm = &xtensa->dbg_mod;

	if (!xtensa->core_config->trace.enabled &&
		(reg <= XDMREG_MEMADDREND || (reg >= XDMREG_PMG && reg <= XDMREG_PMSTAT7))) {
		LOG_ERROR("Can not access %u reg when Trace Port option disabled!", reg);
		return ERROR_FAIL;
	}
	return dm->dbg_ops->queue_reg_read(dm, reg, data);
}

static inline int xtensa_queue_dbg_reg_write(struct xtensa *xtensa, xtensa_dm_reg reg, uint32_t data)
{
	struct xtensa_debug_module *dm = &xtensa->dbg_mod;

	if (!xtensa->core_config->trace.enabled &&
		(reg <= XDMREG_MEMADDREND || (reg >= XDMREG_PMG && reg <= XDMREG_PMSTAT7))) {
		LOG_ERROR("Can not access %u reg when Trace Port option disabled!", reg);
		return ERROR_FAIL;
	}
	return dm->dbg_ops->queue_reg_write(dm, reg, data);
}

static inline int xtensa_queue_pwr_reg_read(struct xtensa *xtensa,
	xtensa_dm_pwr_reg reg,
	uint32_t *data,
	uint32_t clear)
{
	struct xtensa_debug_module *dm = &xtensa->dbg_mod;
	return dm->pwr_ops->queue_reg_read(dm, reg, data, clear);
}

static inline int xtensa_queue_pwr_reg_write(struct xtensa *xtensa, xtensa_dm_pwr_reg reg, uint32_t data)
{
	struct xtensa_debug_module *dm = &xtensa->dbg_mod;
	return dm->pwr_ops->queue_reg_write(dm, reg, data);
}

static inline void xtensa_queue_exec_ins(struct xtensa *xtensa, int32_t ins)
{
	xtensa_queue_dbg_reg_write(xtensa, XDMREG_DIR0EXEC, ins);
}

static inline void xtensa_queue_exec_ins_wide(struct xtensa *xtensa, uint8_t *ops, uint8_t oplen)
{
	if ((oplen > 0) && (oplen <= 64)) {
		uint32_t opsw[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };	/* 8 DIRx regs: max width 64B */
		uint8_t  oplenw = (oplen + 3) / 4;
	    if (xtensa->core_config->bigendian) {
			buf_bswap32((uint8_t *)opsw, ops, oplenw * 4);
		} else {
			memcpy(opsw, ops, oplen);
		}
		for (int32_t i = oplenw - 1; i > 0; i--) {
			xtensa_queue_dbg_reg_write(xtensa, XDMREG_DIR0 + i, opsw[i]);
		}
		/* Write DIR0EXEC last */
		xtensa_queue_dbg_reg_write(xtensa, XDMREG_DIR0EXEC, opsw[0]);
	}
}

int xtensa_init_arch_info(struct target *target,
	struct xtensa *xtensa,
	const struct xtensa_debug_module_config *dm_cfg);
int xtensa_target_init(struct command_context *cmd_ctx, struct target *target);
void xtensa_target_deinit(struct target *target);
int xtensa_build_reg_cache(struct target *target);

static inline void xtensa_stepping_isr_mode_set(struct target *target,
	enum xtensa_stepping_isr_mode mode)
{
	struct xtensa *xtensa = target_to_xtensa(target);
	xtensa->stepping_isr_mode = mode;
}

static inline enum xtensa_stepping_isr_mode xtensa_stepping_isr_mode_get(struct target *target)
{
	struct xtensa *xtensa = target_to_xtensa(target);
	return xtensa->stepping_isr_mode;
}

static inline bool xtensa_addr_in_mem(const struct xtensa_local_mem_config *mem, uint32_t addr)
{
	for (uint16_t i = 0; i < mem->count; i++) {
		if (addr >= mem->regions[i].base &&
			addr < mem->regions[i].base + mem->regions[i].size)
			return true;
	}
	return false;
}

static inline bool xtensa_data_addr_valid(struct target *target, uint32_t addr)
{
	struct xtensa *xtensa = target_to_xtensa(target);

	if (xtensa_addr_in_mem(&xtensa->core_config->drom, addr))
		return true;
	if (xtensa_addr_in_mem(&xtensa->core_config->dram, addr))
		return true;
	if (xtensa_addr_in_mem(&xtensa->core_config->sram, addr))
		return true;
	return false;
}

static inline int xtensa_core_status_clear(struct target *target, xtensa_dsr_t bits)
{
	struct xtensa *xtensa = target_to_xtensa(target);
	return xtensa_dm_core_status_clear(&xtensa->dbg_mod, bits);
}

int xtensa_core_status_check(struct target *target);

int xtensa_examine(struct target *target);
int xtensa_wakeup(struct target *target);
int xtensa_smpbreak_set(struct target *target, uint32_t set);
int xtensa_smpbreak_get(struct target *target, uint32_t *val);
int xtensa_smpbreak_write(struct target *target, uint32_t set);
int xtensa_smpbreak_read(struct target *target, uint32_t *val);
uint32_t xtensa_reg_get(struct target *target, enum xtensa_reg_id reg_id);
void xtensa_reg_set(struct target *target, enum xtensa_reg_id reg_id, uint32_t value);
void xtensa_reg_set_deep_relgen(struct target *target, enum xtensa_reg_id a_idx, uint32_t value);
int xtensa_fetch_all_regs(struct target *target);
int xtensa_get_gdb_reg_list(struct target *target,
	struct reg **reg_list[],
	int *reg_list_size,
	enum target_register_class reg_class);
xtensa_reg_val_t xtensa_cause_get(struct target *target);
void xtensa_cause_clear(struct target *target);
void xtensa_cause_reset(struct target *target);
int xtensa_poll(struct target *target);
void xtensa_on_poll(struct target *target);
bool xtensa_restart_resp_req(struct target *target);
int xtensa_halt(struct target *target);
int xtensa_resume(struct target *target,
	int current,
	target_addr_t address,
	int handle_breakpoints,
	int debug_execution);
int xtensa_prepare_resume(struct target *target,
	int current,
	target_addr_t address,
	int handle_breakpoints,
	int debug_execution);
int xtensa_do_resume(struct target *target);
int xtensa_step(struct target *target,
	int current,
	target_addr_t address,
	int handle_breakpoints);
int xtensa_do_step(struct target *target,
	int current,
	target_addr_t address,
	int handle_breakpoints);
int xtensa_mmu_is_enabled(struct target *target, int *enabled);
int xtensa_read_memory(struct target *target,
	target_addr_t address,
	uint32_t size,
	uint32_t count,
	uint8_t *buffer);
int xtensa_read_buffer(struct target *target,
	target_addr_t address,
	uint32_t count,
	uint8_t *buffer);
int xtensa_write_memory(struct target *target,
	target_addr_t address,
	uint32_t size,
	uint32_t count,
	const uint8_t *buffer);
int xtensa_write_buffer(struct target *target,
	target_addr_t address,
	uint32_t count,
	const uint8_t *buffer);
int xtensa_checksum_memory(struct target *target, target_addr_t address,
	uint32_t count, uint32_t *checksum);
int xtensa_assert_reset(struct target *target);
int xtensa_deassert_reset(struct target *target);
int xtensa_breakpoint_add(struct target *target, struct breakpoint *breakpoint);
int xtensa_breakpoint_remove(struct target *target, struct breakpoint *breakpoint);
int xtensa_watchpoint_add(struct target *target, struct watchpoint *watchpoint);
int xtensa_watchpoint_remove(struct target *target, struct watchpoint *watchpoint);
int xtensa_handle_target_event(struct target *target,
	enum target_event event,
	void *priv);
void xtensa_set_permissive_mode(struct target *target, bool state);
int xtensa_gdb_query_custom(struct target *target, const char *packet, char **response_p);

COMMAND_HELPER(xtensa_cmd_permissive_mode_do, struct xtensa *xtensa);
COMMAND_HELPER(xtensa_cmd_mask_interrupts_do, struct xtensa *xtensa);
COMMAND_HELPER(xtensa_cmd_smpbreak_do, struct target *target);
COMMAND_HELPER(xtensa_cmd_perfmon_dump_do, struct xtensa *xtensa);
COMMAND_HELPER(xtensa_cmd_perfmon_enable_do, struct xtensa *xtensa);
COMMAND_HELPER(xtensa_cmd_tracestart_do, struct xtensa *xtensa);
COMMAND_HELPER(xtensa_cmd_tracestop_do, struct xtensa *xtensa);
COMMAND_HELPER(xtensa_cmd_tracedump_do, struct xtensa *xtensa, const char *fname);

extern const struct command_registration xtensa_command_handlers[];

#endif	/* OPENOCD_TARGET_XTENSA_H */
