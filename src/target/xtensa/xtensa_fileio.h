/***************************************************************************
 *   Xtensa Target File-I/O Support for OpenOCD                            *
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

#ifndef OPENOCD_TARGET_XTENSA_FILEIO_H
#define OPENOCD_TARGET_XTENSA_FILEIO_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <target/target.h>
#include "xtensa.h"

#define XTENSA_SYSCALL_OP_REG		XT_REG_IDX_A2
#define XTENSA_SYSCALL_RETVAL_REG	XT_REG_IDX_A2
#define XTENSA_SYSCALL_ERRNO_REG	XT_REG_IDX_A3

#define XTENSA_SYSCALL_OPEN			(-2)
#define XTENSA_SYSCALL_CLOSE		(-3)
#define XTENSA_SYSCALL_READ			(-4)
#define XTENSA_SYSCALL_WRITE		(-5)
#define XTENSA_SYSCALL_LSEEK		(-6)
#define XTENSA_SYSCALL_RENAME		(-7)
#define XTENSA_SYSCALL_UNLINK		(-8)
#define XTENSA_SYSCALL_STAT			(-9)
#define XTENSA_SYSCALL_FSTAT		(-10)
#define XTENSA_SYSCALL_GETTIMEOFDAY	(-11)
#define XTENSA_SYSCALL_ISATTY		(-12)
#define XTENSA_SYSCALL_SYSTEM		(-13)

int xtensa_fileio_init(struct target *target);
int xtensa_fileio_detect_proc(struct target *target);
int xtensa_get_gdb_fileio_info(struct target *target, struct gdb_fileio_info *fileio_info);
int xtensa_gdb_fileio_end(struct target *target, int retcode, int fileio_errno, bool ctrl_c);

#endif	/* OPENOCD_TARGET_XTENSA_FILEIO_H */
