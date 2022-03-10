/***************************************************************************
 *   Xtensa Debug Module (XDM) Support for OpenOCD                         *
 *   Copyright (C) 2020-2021 Cadence Design Systems, Inc.                  *
 *   Author: Ian Thompson <ianst@cadence.com>                              *
 *                                                                         *
 *   Copyright (C) 2019 Espressif Systems Ltd.                             *
 *   <alexey@espressif.com>                                                *
 *                                                                         *
 *   Derived from original ESP8266 target.                                 *
 *   Copyright (C) 2015 by Angus Gratton                                   *
 *   gus@projectgus.com                                                    *
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
#ifndef __XTENSA_DEBUG_MODULE_H__
#define __XTENSA_DEBUG_MODULE_H__   1

#include <jtag/jtag.h>
#include "arm_adi_v5.h"
#include "target.h"

/* Virtual IDs for using with xtensa_power_ops API */
typedef enum {
	XDMREG_PWRCTL = 0x00,
	XDMREG_PWRSTAT,
	XDMREG_PWRNUM
} xtensa_dm_pwr_reg;

/* Debug Module Power Register offsets within APB */
typedef struct {
	uint16_t apb;
} xtensa_dm_pwr_reg_offsets;

/* Debug Module Power Register offset structure; must include XDMREG_PWRNUM entries */
#define XTENSA_DM_PWR_REG_OFFSETS	{				\
	/* Power/Reset Registers */						\
	{ 0x3020 },			/* XDMREG_PWRCTL */			\
	{ 0x3024 },			/* XDMREG_PWRSTAT */		\
}

/*
 From the manual:
 To properly use Debug registers through JTAG, software must ensure that:
 - Tap is out of reset
 - Xtensa Debug Module is out of reset
 - Other bits of PWRCTL are set to their desired values, and finally
 - JtagDebugUse transitions from 0 to 1
 The bit must continue to be 1 in order for JTAG accesses to the Debug
 Module to happen correctly. When it is set, any write to this bit clears it.
 Either don't access it, or re-write it to 1 so JTAG accesses continue.
*/
#define PWRCTL_JTAGDEBUGUSE(x)		(((x)->dbg_mod.dap) ? (0)     : (1<<7))
#define PWRCTL_DEBUGRESET(x)		(((x)->dbg_mod.dap) ? (1<<28) : (1<<6))
#define PWRCTL_CORERESET(x)			(((x)->dbg_mod.dap) ? (1<<16) : (1<<4))
#define PWRCTL_DEBUGWAKEUP(x)		(((x)->dbg_mod.dap) ? (1<<12) : (1<<2))
#define PWRCTL_MEMWAKEUP(x)			(((x)->dbg_mod.dap) ? (1<<8)  : (1<<1))
#define PWRCTL_COREWAKEUP(x)		(((x)->dbg_mod.dap) ? (1<<0)  : (1<<0))

#define PWRSTAT_DEBUGWASRESET_DM(d)	(((d)->dap) ? (1<<28) : (1<<6))
#define PWRSTAT_COREWASRESET_DM(d)	(((d)->dap) ? (1<<16) : (1<<4))
#define PWRSTAT_DEBUGWASRESET(x)	(PWRSTAT_DEBUGWASRESET_DM(&((x)->dbg_mod)))
#define PWRSTAT_COREWASRESET(x)		(PWRSTAT_COREWASRESET_DM(&((x)->dbg_mod)))
#define PWRSTAT_CORESTILLNEEDED(x)	(((x)->dbg_mod.dap) ? (1<<4)  : (1<<3))
#define PWRSTAT_DEBUGDOMAINON(x)	(((x)->dbg_mod.dap) ? (1<<12) : (1<<2))
#define PWRSTAT_MEMDOMAINON(x)		(((x)->dbg_mod.dap) ? (1<<8)  : (1<<1))
#define PWRSTAT_COREDOMAINON(x)		(((x)->dbg_mod.dap) ? (1<<0)  : (1<<0))

/* Virtual IDs for using with xtensa_debug_ops API */
typedef enum {
	/* TRAX Registers */
	XDMREG_TRAXID = 0x00,
	XDMREG_TRAXCTRL,
	XDMREG_TRAXSTAT,
	XDMREG_TRAXDATA,
	XDMREG_TRAXADDR,
	XDMREG_TRIGGERPC,
	XDMREG_PCMATCHCTRL,
	XDMREG_DELAYCNT,
	XDMREG_MEMADDRSTART,
	XDMREG_MEMADDREND,

	/* Performance Monitor Registers */
	XDMREG_PMG,
	XDMREG_INTPC,
	XDMREG_PM0,
	XDMREG_PM1,
	XDMREG_PM2,
	XDMREG_PM3,
	XDMREG_PM4,
	XDMREG_PM5,
	XDMREG_PM6,
	XDMREG_PM7,
	XDMREG_PMCTRL0,
	XDMREG_PMCTRL1,
	XDMREG_PMCTRL2,
	XDMREG_PMCTRL3,
	XDMREG_PMCTRL4,
	XDMREG_PMCTRL5,
	XDMREG_PMCTRL6,
	XDMREG_PMCTRL7,
	XDMREG_PMSTAT0,
	XDMREG_PMSTAT1,
	XDMREG_PMSTAT2,
	XDMREG_PMSTAT3,
	XDMREG_PMSTAT4,
	XDMREG_PMSTAT5,
	XDMREG_PMSTAT6,
	XDMREG_PMSTAT7,

	/* OCD Registers */
	XDMREG_OCDID,
	XDMREG_DCRCLR,
	XDMREG_DCRSET,
	XDMREG_DSR,
	XDMREG_DDR,
	XDMREG_DDREXEC,
	XDMREG_DIR0EXEC,
	XDMREG_DIR0,
	XDMREG_DIR1,
	XDMREG_DIR2,
	XDMREG_DIR3,
	XDMREG_DIR4,
	XDMREG_DIR5,
	XDMREG_DIR6,
	XDMREG_DIR7,

	/* Misc Registers */
	XDMREG_ERISTAT,

	/* CoreSight Registers */
	XDMREG_ITCTRL,
	XDMREG_CLAIMSET,
	XDMREG_CLAIMCLR,
	XDMREG_LOCKACCESS,
	XDMREG_LOCKSTATUS,
	XDMREG_AUTHSTATUS,
	XDMREG_DEVID,
	XDMREG_DEVTYPE,
	XDMREG_PERID4,
	XDMREG_PERID5,
	XDMREG_PERID6,
	XDMREG_PERID7,
	XDMREG_PERID0,
	XDMREG_PERID1,
	XDMREG_PERID2,
	XDMREG_PERID3,
	XDMREG_COMPID0,
	XDMREG_COMPID1,
	XDMREG_COMPID2,
	XDMREG_COMPID3,

	XDMREG_NUM
} xtensa_dm_reg;

/* Debug Module Register offsets within Nexus (NAR) or APB */
typedef struct {
	uint8_t  nar;
	uint16_t apb;
} xtensa_dm_reg_offsets;

/* Debug Module Register offset structure; must include XDMREG_NUM entries */
#define XTENSA_DM_REG_OFFSETS	{					\
	/* TRAX Registers */							\
	{ 0x00, 0x0000 },	/* XDMREG_TRAXID */			\
	{ 0x01, 0x0004 },	/* XDMREG_TRAXCTRL */		\
	{ 0x02, 0x0008 },	/* XDMREG_TRAXSTAT */		\
	{ 0x03, 0x000c },	/* XDMREG_TRAXDATA */		\
	{ 0x04, 0x0010 },	/* XDMREG_TRAXADDR */		\
	{ 0x05, 0x0014 },	/* XDMREG_TRIGGERPC */		\
	{ 0x06, 0x0018 },	/* XDMREG_PCMATCHCTRL */	\
	{ 0x07, 0x001c },	/* XDMREG_DELAYCNT */		\
	{ 0x08, 0x0020 },	/* XDMREG_MEMADDRSTART */	\
	{ 0x09, 0x0024 },	/* XDMREG_MEMADDREND */		\
													\
	/* Performance Monitor Registers */				\
	{ 0x20, 0x1000 },	/* XDMREG_PMG */			\
	{ 0x24, 0x1010 },	/* XDMREG_INTPC */			\
	{ 0x28, 0x1080 },	/* XDMREG_PM0 */			\
	{ 0x29, 0x1084 },	/* XDMREG_PM1 */			\
	{ 0x2a, 0x1088 },	/* XDMREG_PM2 */			\
	{ 0x2b, 0x108c },	/* XDMREG_PM3 */			\
	{ 0x2c, 0x1090 },	/* XDMREG_PM4 */			\
	{ 0x2d, 0x1094 },	/* XDMREG_PM5 */			\
	{ 0x2e, 0x1098 },	/* XDMREG_PM6 */			\
	{ 0x2f, 0x109c },	/* XDMREG_PM7 */			\
	{ 0x30, 0x1100 },	/* XDMREG_PMCTRL0 */		\
	{ 0x31, 0x1104 },	/* XDMREG_PMCTRL1 */		\
	{ 0x32, 0x1108 },	/* XDMREG_PMCTRL2 */		\
	{ 0x33, 0x110c },	/* XDMREG_PMCTRL3 */		\
	{ 0x34, 0x1110 },	/* XDMREG_PMCTRL4 */		\
	{ 0x35, 0x1114 },	/* XDMREG_PMCTRL5 */		\
	{ 0x36, 0x1118 },	/* XDMREG_PMCTRL6 */		\
	{ 0x37, 0x111c },	/* XDMREG_PMCTRL7 */		\
	{ 0x38, 0x1180 },	/* XDMREG_PMSTAT0 */		\
	{ 0x39, 0x1184 },	/* XDMREG_PMSTAT1 */		\
	{ 0x3a, 0x1188 },	/* XDMREG_PMSTAT2 */		\
	{ 0x3b, 0x118c },	/* XDMREG_PMSTAT3 */		\
	{ 0x3c, 0x1190 },	/* XDMREG_PMSTAT4 */		\
	{ 0x3d, 0x1194 },	/* XDMREG_PMSTAT5 */		\
	{ 0x3e, 0x1198 },	/* XDMREG_PMSTAT6 */		\
	{ 0x3f, 0x119c },	/* XDMREG_PMSTAT7 */		\
													\
	/* OCD Registers */								\
	{ 0x40, 0x2000 },	/* XDMREG_OCDID */			\
	{ 0x42, 0x2008 },	/* XDMREG_DCRCLR */			\
	{ 0x43, 0x200c },	/* XDMREG_DCRSET */			\
	{ 0x44, 0x2010 },	/* XDMREG_DSR */			\
	{ 0x45, 0x2014 },	/* XDMREG_DDR */			\
	{ 0x46, 0x2018 },	/* XDMREG_DDREXEC */		\
	{ 0x47, 0x201c },	/* XDMREG_DIR0EXEC */		\
	{ 0x48, 0x2020 },	/* XDMREG_DIR0 */			\
	{ 0x49, 0x2024 },	/* XDMREG_DIR1 */			\
	{ 0x4a, 0x2028 },	/* XDMREG_DIR2 */			\
	{ 0x4b, 0x202c },	/* XDMREG_DIR3 */			\
	{ 0x4c, 0x2030 },	/* XDMREG_DIR4 */			\
	{ 0x4d, 0x2034 },	/* XDMREG_DIR5 */			\
	{ 0x4e, 0x2038 },	/* XDMREG_DIR6 */			\
	{ 0x4f, 0x203c },	/* XDMREG_DIR7 */			\
													\
	/* Misc Registers */							\
	{ 0x5a, 0x3028 },	/* XDMREG_ERISTAT */		\
													\
	/* CoreSight Registers */						\
	{ 0x60, 0x3f00 },	/* XDMREG_ITCTRL */			\
	{ 0x68, 0x3fa0 },	/* XDMREG_CLAIMSET */		\
	{ 0x69, 0x3fa4 },	/* XDMREG_CLAIMCLR */		\
	{ 0x6c, 0x3fb0 },	/* XDMREG_LOCKACCESS */		\
	{ 0x6d, 0x3fb4 },	/* XDMREG_LOCKSTATUS */		\
	{ 0x6e, 0x3fb8 },	/* XDMREG_AUTHSTATUS */		\
	{ 0x72, 0x3fc8 },	/* XDMREG_DEVID */			\
	{ 0x73, 0x3fcc },	/* XDMREG_DEVTYPE */		\
	{ 0x74, 0x3fd0 },	/* XDMREG_PERID4 */			\
	{ 0x75, 0x3fd4 },	/* XDMREG_PERID5 */			\
	{ 0x76, 0x3fd8 },	/* XDMREG_PERID6 */			\
	{ 0x77, 0x3fdc },	/* XDMREG_PERID7 */			\
	{ 0x78, 0x3fe0 },	/* XDMREG_PERID0 */			\
	{ 0x79, 0x3fe4 },	/* XDMREG_PERID1 */			\
	{ 0x7a, 0x3fe8 },	/* XDMREG_PERID2 */			\
	{ 0x7b, 0x3fec },	/* XDMREG_PERID3 */			\
	{ 0x7c, 0x3ff0 },	/* XDMREG_COMPID0 */		\
	{ 0x7d, 0x3ff4 },	/* XDMREG_COMPID1 */		\
	{ 0x7e, 0x3ff8 },	/* XDMREG_COMPID2 */		\
	{ 0x7f, 0x3ffc },	/* XDMREG_COMPID3 */		\
}

#define XTENSA_DM_APB_MASK		(0x3fff)

/*OCD registers, bit definitions */
#define OCDDCR_ENABLEOCD        (1<<0)
#define OCDDCR_DEBUGINTERRUPT   (1<<1)
#define OCDDCR_INTERRUPTALLCONDS    (1<<2)
#define OCDDCR_BREAKINEN        (1<<16)
#define OCDDCR_BREAKOUTEN       (1<<17)
#define OCDDCR_DEBUGSWACTIVE    (1<<20)
#define OCDDCR_RUNSTALLINEN     (1<<21)
#define OCDDCR_DEBUGMODEOUTEN   (1<<22)
#define OCDDCR_BREAKOUTITO      (1<<24)
#define OCDDCR_BREAKACKITO      (1<<25)

#define OCDDSR_EXECDONE         (1<<0)
#define OCDDSR_EXECEXCEPTION    (1<<1)
#define OCDDSR_EXECBUSY         (1<<2)
#define OCDDSR_EXECOVERRUN      (1<<3)
#define OCDDSR_STOPPED          (1<<4)
#define OCDDSR_COREWROTEDDR     (1<<10)
#define OCDDSR_COREREADDDR      (1<<11)
#define OCDDSR_HOSTWROTEDDR     (1<<14)
#define OCDDSR_HOSTREADDDR      (1<<15)
#define OCDDSR_DEBUGPENDBREAK   (1<<16)
#define OCDDSR_DEBUGPENDHOST    (1<<17)
#define OCDDSR_DEBUGPENDTRAX    (1<<18)
#define OCDDSR_DEBUGINTBREAK    (1<<20)
#define OCDDSR_DEBUGINTHOST     (1<<21)
#define OCDDSR_DEBUGINTTRAX     (1<<22)
#define OCDDSR_RUNSTALLTOGGLE   (1<<23)
#define OCDDSR_RUNSTALLSAMPLE   (1<<24)
#define OCDDSR_BREACKOUTACKITI  (1<<25)
#define OCDDSR_BREAKINITI       (1<<26)
#define OCDDSR_DBGMODPOWERON    (1U<<31)

#define DEBUGCAUSE_IC           (1<<0)	/*ICOUNT exception */
#define DEBUGCAUSE_IB           (1<<1)	/*IBREAK exception */
#define DEBUGCAUSE_DB           (1<<2)	/*DBREAK exception */
#define DEBUGCAUSE_BI           (1<<3)	/*BREAK instruction encountered */
#define DEBUGCAUSE_BN           (1<<4)	/*BREAK.N instruction encountered */
#define DEBUGCAUSE_DI           (1<<5)	/*Debug Interrupt */

#define TRAXCTRL_TREN           (1<<0)	/*Trace enable. Tracing starts on 0->1 */
#define TRAXCTRL_TRSTP          (1<<1)	/*Trace Stop. Make 1 to stop trace. */
#define TRAXCTRL_PCMEN          (1<<2)	/*PC match enable */
#define TRAXCTRL_PTIEN          (1<<4)	/*Processor-trigger enable */
#define TRAXCTRL_CTIEN          (1<<5)	/*Cross-trigger enable */
#define TRAXCTRL_TMEN           (1<<7)	/*Tracemem Enable. Always set. */
#define TRAXCTRL_CNTU           (1<<9)	/*Post-stop-trigger countdown units; selects when
					 * DelayCount-- happens. */
					/*0 - every 32-bit word written to tracemem, 1 - every cpu
					 * instruction */
#define TRAXCTRL_TSEN           (1<<11)	/*Undocumented/deprecated? */
#define TRAXCTRL_SMPER_SHIFT    12	/*Send sync every 2^(9-smper) messages. 7=reserved, 0=no
					 * sync msg */
#define TRAXCTRL_SMPER_MASK     0x7	/*Synchronization message period */
#define TRAXCTRL_PTOWT          (1<<16)	/*Processor Trigger Out (OCD halt) enabled when stop
					 * triggered */
#define TRAXCTRL_PTOWS          (1<<17)	/*Processor Trigger Out (OCD halt) enabled when trace stop
					 * completes */
#define TRAXCTRL_CTOWT          (1<<20)	/*Cross-trigger Out enabled when stop triggered */
#define TRAXCTRL_CTOWS          (1<<21)	/*Cross-trigger Out enabled when trace stop completes */
#define TRAXCTRL_ITCTO          (1<<22)	/*Integration mode: cross-trigger output */
#define TRAXCTRL_ITCTIA         (1<<23)	/*Integration mode: cross-trigger ack */
#define TRAXCTRL_ITATV          (1<<24)	/*replaces ATID when in integration mode: ATVALID output */
#define TRAXCTRL_ATID_MASK      0x7F	/*ARB source ID */
#define TRAXCTRL_ATID_SHIFT     24
#define TRAXCTRL_ATEN           (1U<<31)	/*ATB interface enable */

#define TRAXSTAT_TRACT          (1<<0)	/*Trace active flag. */
#define TRAXSTAT_TRIG           (1<<1)	/*Trace stop trigger. Clears on TREN 1->0 */
#define TRAXSTAT_PCMTG          (1<<2)	/*Stop trigger caused by PC match. Clears on TREN 1->0 */
#define TRAXSTAT_PJTR           (1<<3)	/*JTAG transaction result. 1=err in preceding jtag
					 * transaction. */
#define TRAXSTAT_PTITG          (1<<4)	/*Stop trigger caused by Processor Trigger Input. Clears on
					 * TREN 1->0 */
#define TRAXSTAT_CTITG          (1<<5)	/*Stop trigger caused by Cross-Trigger Input. Clears on TREN
					 * 1->0 */
#define TRAXSTAT_MEMSZ_SHIFT    8	/*Traceram size inducator. Usable trace ram is 2^MEMSZ
					 * bytes. */
#define TRAXSTAT_MEMSZ_MASK     0x1F
#define TRAXSTAT_PTO            (1<<16)	/*Processor Trigger Output: current value */
#define TRAXSTAT_CTO            (1<<17)	/*Cross-Trigger Output: current value */
#define TRAXSTAT_ITCTOA         (1<<22)	/*Cross-Trigger Out Ack: current value */
#define TRAXSTAT_ITCTI          (1<<23)	/*Cross-Trigger Input: current value */
#define TRAXSTAT_ITATR          (1<<24)	/*ATREADY Input: current value */

#define TRAXADDR_TADDR_SHIFT    0	/*Trax memory address, in 32-bit words. */
#define TRAXADDR_TADDR_MASK     0x1FFFFF/*Actually is only as big as the trace buffer size max addr.
					 * */
#define TRAXADDR_TWRAP_SHIFT    21	/*Amount of times TADDR has overflown */
#define TRAXADDR_TWRAP_MASK     0x3FF
#define TRAXADDR_TWSAT          (1U<<31)	/*1 if TWRAP has overflown, clear by disabling tren.
						 **/

#define PCMATCHCTRL_PCML_SHIFT  0	/*Amount of lower bits to ignore in pc trigger register */
#define PCMATCHCTRL_PCML_MASK   0x1F
#define PCMATCHCTRL_PCMS        (1U<<31)	/*PC Match Sense, 0 - match when procs PC is in-range, 1 -
						* match when */
/*out-of-range */

#define XTENSA_MAX_PERF_COUNTERS    2
#define XTENSA_MAX_PERF_SELECT      32
#define XTENSA_MAX_PERF_MASK        0xffff

struct xtensa_debug_module;

struct xtensa_debug_ops {
	/** enable operation */
	int (*queue_enable)(struct xtensa_debug_module *dm);
	/** register read. */
	int (*queue_reg_read)(struct xtensa_debug_module *dm, xtensa_dm_reg reg, uint32_t *data);
	/** register write. */
	int (*queue_reg_write)(struct xtensa_debug_module *dm, xtensa_dm_reg reg, uint32_t data);
};

struct xtensa_power_ops {
	/** register read. */
	int (*queue_reg_read)(struct xtensa_debug_module *dm, xtensa_dm_pwr_reg reg, uint32_t *data,
		uint32_t clear);
	/** register write. */
	int (*queue_reg_write)(struct xtensa_debug_module *dm, xtensa_dm_pwr_reg reg, uint32_t data);
};

typedef uint32_t xtensa_pwrstat_t;
typedef uint32_t xtensa_ocdid_t;
typedef uint32_t xtensa_dsr_t;
typedef uint32_t xtensa_traxstat_t;


struct xtensa_power_status {
	xtensa_pwrstat_t stat;
	xtensa_pwrstat_t stath;
	/* TODO: do not need to keep previous status to detect that core or debug module has been
	 * reset, */
	/*       we can clear PWRSTAT_DEBUGWASRESET and PWRSTAT_COREWASRESET after reading will do
	 * the job; */
	/*       upon next reet those bits will be set again. So we can get rid of
	 *       xtensa_dm_power_status_cache_reset() and xtensa_dm_power_status_cache(). */
	xtensa_pwrstat_t prev_stat;
};

struct xtensa_core_status {
	xtensa_dsr_t dsr;
};

struct xtensa_trace_config {
	uint32_t ctrl;
	uint32_t memaddr_start;
	uint32_t memaddr_end;
	uint32_t addr;
};

struct xtensa_trace_status {
	xtensa_traxstat_t stat;
};

struct xtensa_trace_start_config {
	uint32_t stoppc;
	bool after_is_words;
	uint32_t after;
	uint32_t stopmask;	/* -1: disable PC match option */
};

struct xtensa_perfmon_config {
	int select;
	uint32_t mask;
	int kernelcnt;
	int tracelevel;
};

struct xtensa_perfmon_result {
	uint64_t value;
	bool overflow;
};

struct xtensa_debug_module_config {
	const struct xtensa_power_ops *pwr_ops;
	const struct xtensa_debug_ops *dbg_ops;

	/* Either JTAG or DAP structures will be populated */
	struct jtag_tap *tap;
	void (*queue_tdi_idle)(struct target *target);
	void *queue_tdi_idle_arg;

	/* For targets conforming to ARM Debug Interface v5,
	 * "dap" references the Debug Access Port (DAP)
	 * used to make requests to the target;
	 * "debug_ap" is AP instance connected to processor
	 */
	struct adiv5_dap *dap;
	struct adiv5_ap *debug_ap;
	int debug_apsel;
	uint32_t ap_offset;
};

struct xtensa_debug_module {
	const struct xtensa_power_ops *pwr_ops;
	const struct xtensa_debug_ops *dbg_ops;

	/* Either JTAG or DAP structures will be populated */
	struct jtag_tap *tap;
	void (*queue_tdi_idle)(struct target *target);
	void *queue_tdi_idle_arg;

	/* DAP struct; AP instance connected to processor */
    struct adiv5_dap *dap;
    struct adiv5_ap *debug_ap;
    int debug_apsel;

	struct xtensa_power_status power_status;
	struct xtensa_core_status core_status;
	xtensa_ocdid_t device_id;
	uint32_t ap_offset;
};


int xtensa_dm_init(struct xtensa_debug_module *dm, const struct xtensa_debug_module_config *cfg);
int xtensa_dm_examine(struct xtensa_debug_module *dm);
int xtensa_dm_set_offset(struct xtensa_debug_module *dm, uint32_t offset);
int xtensa_dm_queue_enable(struct xtensa_debug_module *dm);
int xtensa_dm_queue_reg_read(struct xtensa_debug_module *dm, xtensa_dm_reg reg, uint32_t *value);
int xtensa_dm_queue_reg_write(struct xtensa_debug_module *dm, xtensa_dm_reg reg, uint32_t value);
int xtensa_dm_queue_pwr_reg_read(struct xtensa_debug_module *dm,
	xtensa_dm_pwr_reg reg,
	uint32_t *data,
	uint32_t clear);
int xtensa_dm_queue_pwr_reg_write(struct xtensa_debug_module *dm, 
	xtensa_dm_pwr_reg reg, 
	uint32_t data);

static inline int xtensa_dm_queue_execute(struct xtensa_debug_module *dm)
{
	return dm->dap ? dap_run(dm->dap) : jtag_execute_queue();
}

static inline void xtensa_dm_queue_tdi_idle(struct xtensa_debug_module *dm)
{
	if (dm->queue_tdi_idle)
		dm->queue_tdi_idle(dm->queue_tdi_idle_arg);
}

int xtensa_dm_power_status_read(struct xtensa_debug_module *dm, uint32_t clear);
static inline void xtensa_dm_power_status_cache_reset(struct xtensa_debug_module *dm)
{
	dm->power_status.prev_stat = 0;
}
static inline void xtensa_dm_power_status_cache(struct xtensa_debug_module *dm)
{
	dm->power_status.prev_stat = dm->power_status.stath;
}
static inline xtensa_pwrstat_t xtensa_dm_power_status_get(struct xtensa_debug_module *dm)
{
	return dm->power_status.stat;
}

int xtensa_dm_core_status_read(struct xtensa_debug_module *dm);
int xtensa_dm_core_status_clear(struct xtensa_debug_module *dm, xtensa_dsr_t bits);
int xtensa_dm_core_status_check(struct xtensa_debug_module *dm);
static inline xtensa_dsr_t xtensa_dm_core_status_get(struct xtensa_debug_module *dm)
{
	return dm->core_status.dsr;
}

int xtensa_dm_device_id_read(struct xtensa_debug_module *dm);
static inline xtensa_ocdid_t xtensa_dm_device_id_get(struct xtensa_debug_module *dm)
{
	return dm->device_id;
}

int xtensa_dm_trace_start(struct xtensa_debug_module *dm, struct xtensa_trace_start_config *cfg);
int xtensa_dm_trace_stop(struct xtensa_debug_module *dm);
int xtensa_dm_trace_config_read(struct xtensa_debug_module *dm, struct xtensa_trace_config *config);
int xtensa_dm_trace_status_read(struct xtensa_debug_module *dm, struct xtensa_trace_status *status);
int xtensa_dm_trace_data_read(struct xtensa_debug_module *dm, uint8_t *dest, uint32_t size);

static inline bool xtensa_dm_is_online(struct xtensa_debug_module *dm)
{
	int res = xtensa_dm_device_id_read(dm);
	if (res != ERROR_OK)
		return false;
	return (dm->device_id != 0xffffffff && dm->device_id != 0);
}

static inline bool xtensa_dm_tap_was_reset(struct xtensa_debug_module *dm)
{
	return (!(dm->power_status.prev_stat & PWRSTAT_DEBUGWASRESET_DM(dm)) &&
		dm->power_status.stat & PWRSTAT_DEBUGWASRESET_DM(dm));
}

static inline bool xtensa_dm_core_was_reset(struct xtensa_debug_module *dm)
{
	return (!(dm->power_status.prev_stat & PWRSTAT_COREWASRESET_DM(dm)) &&
		dm->power_status.stat & PWRSTAT_COREWASRESET_DM(dm));
}

static inline bool xtensa_dm_core_is_stalled(struct xtensa_debug_module *dm)
{
	return dm->core_status.dsr & OCDDSR_RUNSTALLSAMPLE;
}

static inline bool xtensa_dm_is_powered(struct xtensa_debug_module *dm)
{
	return dm->core_status.dsr & OCDDSR_DBGMODPOWERON;
}

int xtensa_dm_perfmon_enable(struct xtensa_debug_module *dm, int counter_id,
	const struct xtensa_perfmon_config *config);
int xtensa_dm_perfmon_dump(struct xtensa_debug_module *dm, int counter_id,
	struct xtensa_perfmon_result *out_result);

#endif	/*__XTENSA_DEBUG_MODULE_H__*/
