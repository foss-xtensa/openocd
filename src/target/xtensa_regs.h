/***************************************************************************
 *   Xtensa Target Support for OpenOCD                                     *
 *   Copyright (C) 2020-2021 Cadence Design Systems, Inc.                  *
 *   Author: Ian Thompson <ianst@cadence.com>                              *
 *                                                                         *
 *   Copyright (C) 2016-2019 Espressif Systems Ltd.                        *
 *   Author: Angus Gratton gus@projectgus.com                              *
 *   Author: Jeroen Domburg <jeroen@espressif.com>                         *
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

/*Xtensa register list taken from gdb/gdb/xtensa-config.c
 *gdb wants the registers in the order gdb/regformats/reg-xtensa.dat describes
 *them. The enum and xtensa_regs structs should be in the same order. */

enum xtensa_reg_id {
	XT_REG_IDX_PC = 0,
	XT_REG_IDX_AR0,
	XT_REG_IDX_ARFIRST = XT_REG_IDX_AR0,
	XT_REG_IDX_AR1,
	XT_REG_IDX_AR2,
	XT_REG_IDX_AR3,
	XT_REG_IDX_AR4,
	XT_REG_IDX_AR5,
	XT_REG_IDX_AR6,
	XT_REG_IDX_AR7,
	XT_REG_IDX_AR8,
	XT_REG_IDX_AR9,
	XT_REG_IDX_AR10,
	XT_REG_IDX_AR11,
	XT_REG_IDX_AR12,
	XT_REG_IDX_AR13,
	XT_REG_IDX_AR14,
	XT_REG_IDX_AR15,
	XT_REG_IDX_ARLAST = XT_REG_IDX_AR15 + 48,	/* Max 64 ARs */
	XT_REG_IDX_WINDOWBASE,
	XT_REG_IDX_WINDOWSTART,
	XT_REG_IDX_PS,
	XT_REG_IDX_IBREAKENABLE,
	XT_REG_IDX_DDR,
	XT_REG_IDX_IBREAKA0,
	XT_REG_IDX_IBREAKA1,
	XT_REG_IDX_DBREAKA0,
	XT_REG_IDX_DBREAKA1,
	XT_REG_IDX_DBREAKC0,
	XT_REG_IDX_DBREAKC1,
	XT_REG_IDX_CPENABLE,
	XT_REG_IDX_EXCCAUSE,
	XT_REG_IDX_DEBUGCAUSE,
	XT_REG_IDX_ICOUNT,
	XT_REG_IDX_ICOUNTLEVEL,
	XT_REG_IDX_A0,
	XT_REG_IDX_A1,
	XT_REG_IDX_A2,
	XT_REG_IDX_A3,
	XT_REG_IDX_A4,
	XT_REG_IDX_A5,
	XT_REG_IDX_A6,
	XT_REG_IDX_A7,
	XT_REG_IDX_A8,
	XT_REG_IDX_A9,
	XT_REG_IDX_A10,
	XT_REG_IDX_A11,
	XT_REG_IDX_A12,
	XT_REG_IDX_A13,
	XT_REG_IDX_A14,
	XT_REG_IDX_A15,
	XT_NUM_REGS
};

#define XT_NUM_A_REGS	16

typedef uint32_t xtensa_reg_val_t;

enum xtensa_reg_type_t {
	XT_REG_GENERAL	= 0,	/* General-purpose register; part of the windowed register set */
	XT_REG_USER		= 1,	/* User register, needs RUR to read */
	XT_REG_SPECIAL	= 2,	/* Special register, needs RSR to read */
	XT_REG_DEBUG	= 3,	/* Register used for the debug interface. Don't mess with this. */
	XT_REG_RELGEN	= 4,	/* Relative general address. Points to the absolute
	                  		 * addresses plus the window index */
	XT_REG_TIE		= 5,	/* TIE (custom) register */
	XT_REG_OTHER	= 6,	/* Other (typically legacy) register */
	XT_REG_TYPE_NUM,

	/* enum names must be one of the above types + _VAL or _MASK */
	XT_REG_GENERAL_MASK		= 0xFFC0,
	XT_REG_GENERAL_VAL		= 0x0100,
	XT_REG_USER_MASK		= 0xFF00,
	XT_REG_USER_VAL			= 0x0300,
	XT_REG_SPECIAL_MASK		= 0xFF00,
	XT_REG_SPECIAL_VAL		= 0x0200,
	XT_REG_DEBUG_MASK		= 0xFF00,
	XT_REG_DEBUG_VAL		= 0x0200,
	XT_REG_RELGEN_MASK		= 0xFFE0,
	XT_REG_RELGEN_VAL		= 0x0000,
	XT_REG_TIE_MASK			= 0xF000,
	XT_REG_TIE_VAL			= 0xF000,	/* unused */
	XT_REG_OTHER_MASK		= 0xFFFF,
	XT_REG_OTHER_VAL		= 0xF000,	/* unused */

	XT_REG_INDEX_MASK		= 0x00FF
};

enum xtensa_reg_flags_t {
	XT_REGF_NOREAD	= 0x01,	/* Register is write-only */
	XT_REGF_COPROC0	= 0x02	/* Can't be read if coproc0 isn't enabled */
};

struct xtensa_reg_desc {
	const char *name;
	bool exist;
	int reg_num;                /* ISA register num (meaning depends on register type) */
	int dbreg_num;              /* Debugger-visible register num (reg type encoded) */
	enum xtensa_reg_type_t type;
	enum xtensa_reg_flags_t flags;
};


#define _XT_MK_DBREGN(reg_num, reg_type)                \
    (( reg_type ## _VAL ) | ( reg_num ))

#define _XT_MK_DBREGN_MASK(reg_num, reg_mask)           \
    (( reg_mask ) | ( reg_num ))

#define XT_MK_REG_DESC(name, reg_num, type, flags)      \
    { name, false, (reg_num), _XT_MK_DBREGN( reg_num, type ), (type), (flags) }

extern struct xtensa_reg_desc xtensa_regs[XT_NUM_REGS];
