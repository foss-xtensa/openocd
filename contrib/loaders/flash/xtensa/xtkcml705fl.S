/* SPDX-License-Identifier: GPL-2.0-or-later */

/***************************************************************************
 *   Xtensa flasher for KC705/ML605 platforms
 *   Copyright (C) 2023 Cadence Design Systems
 ***************************************************************************/

/*
 * Parameters:
 * a10 = flash base (in), status (out)
 * a11 = count (halfword-16bit)
 * a12 = buffer start
 * a13 = buffer end / scratch register
 * a14 = target address
 *
 * NOTE: if count does not indicate a multiple of 32 bytes, this logic
 * will round up to and program the next multiple of 32 bytes.
 */
    .text

    .align  4
_flash_prog_start:
	j	_flash_prog

	.align 4
	.literal_position

_flash_prog:
	movi	a13, 0x50		/* clear flash status register */
	s16i	a13, a10, 0

_flash_prog_loop:
	movi	a13, 0xe8		/* set flash into buffer program mode */
	s16i	a13, a14, 0
	movi	a13, 31			/* always program chunks of N=32 bytes (write N-1) */
	s16i	a13, a14, 0
	.set	i, 0
	.rept	32
		l16ui	a13, a12, i
		s16i	a13, a14, i
		.set	i, i+2
	.endr
	movi	a13, 32
	sub		a11, a11, a13	/* increment half-word count */
	add		a13, a13, a13	/* double a13 for incrementing buffer/target addresses */
	add		a12, a12, a13
	add		a14, a14, a13
	movi    a13, 0xd0		/* end buffer program mode */
	s16i	a13, a14, 0
_flash_prog_status_check:
	l16ui	a13, a10, 0
	bbci	a13, 7, _flash_prog_status_check
	extui	a13, a13, 0, 7
	bnez	a13, _flash_prog_error
	bgei	a11, 1, _flash_prog_loop

_flash_prog_done:
    /* TODO: set program mode size of -1? */
    movi	a13, 0x50		/* clear status register */
    s16i	a13, a10, 0
    movi	a13, 0xff		/* restore read array (normal) mode */
    s16i	a13, a10, 0
    movi	a10, 0
    break	0, 0			/* Coded breakpoint at end of algo */
_flash_prog_error:
    movi	a10, -4
    break	0, 0			/* Coded breakpoint at end of algo */

_idle_loop:
    j _idle_loop

