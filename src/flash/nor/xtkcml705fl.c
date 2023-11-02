// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Generic Xtensa KC705 / ML605 flash driver                             *
 *   Copyright (C) 2020-2023 Cadence Design Systems, Inc.                  *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "imp.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/xtensa/xtensa.h>


#define FLASHADDR 0x90000000              /* Defines for KC705 */
#define FLASHSIZE 0x08000000              /* 128MB */
#define FLASHTOP  (FLASHADDR + FLASHSIZE)
#define BLOCKSIZE 0x20000                 /* size of regular block (bytes) */

#define PROGRAM_SUSPEND_CMD  0xB0         /* Program suspend command */
#define PROGRAM_RESUME_CMD   0xD0         /* Program resume command */


struct xtkcml705fl_options {
	uint8_t rdp;
	uint8_t user;
	uint16_t data;
	uint32_t protection;
};

struct xtkcml705fl_flash_bank {
	struct xtkcml705fl_options option_bytes;
	int ppage_size;
	bool probed;

	bool has_dual_banks;
	/* used to access dual flash bank xtkcml705fll */
	bool can_load_options;
	uint32_t register_base;
	uint8_t default_rdp;
	int user_data_offset;
	int option_offset;
	uint32_t user_bank_size;
};


static inline uint16_t flashread(struct flash_bank *bank, target_addr_t addr)
{
	struct target *target = bank->target;
	uint16_t val;
	int status = target_read_u16(target, addr, &val);
	if (status != ERROR_OK) {
		LOG_ERROR("Read flash 0x%lx failed: %d", addr, status);
		return ERROR_FLASH_OPERATION_FAILED;
	}
	return val;
}

static inline void flashwrite(struct flash_bank *bank, target_addr_t addr, uint16_t data)
{
	struct target *target = bank->target;
	int status = target_write_u16(target, addr, data);
	if (status != ERROR_OK)
		LOG_ERROR("Write flash 0x%lx failed: %d", addr, status);
}


/* flash bank xtkcml705fl <base> <size> 0 0 <target#>
 */
FLASH_BANK_COMMAND_HANDLER(xtkcml705fl_flash_bank_command)
{
	struct xtkcml705fl_flash_bank *xtkcml705fl_info;

	LOG_DEBUG("Flash bank starting...");

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	xtkcml705fl_info = malloc(sizeof(struct xtkcml705fl_flash_bank));

	bank->driver_priv = xtkcml705fl_info;
	xtkcml705fl_info->probed = false;
	xtkcml705fl_info->has_dual_banks = false;
	xtkcml705fl_info->can_load_options = false;
//	xtkcml705fl_info->register_base = FLASH_REG_BASE_B0;
	xtkcml705fl_info->register_base = 0;
	xtkcml705fl_info->user_bank_size = bank->size;

	/* The flash write must be aligned to a halfword boundary */
	bank->write_start_alignment = 2;
	bank->write_end_alignment = 2;

	LOG_DEBUG("status: OK");
	return ERROR_OK;
}

static int xtkcml705fl_probe(struct flash_bank *bank)
{
	struct xtkcml705fl_flash_bank *xtkcml705fl_info = bank->driver_priv;
	uint16_t flash_size_in_kb;
	//uint16_t max_flash_size_in_kb;
	//uint32_t dbgmcu_idcode;
	int page_size;
	uint32_t base_address = 0x90000000;

	xtkcml705fl_info->probed = false;
	xtkcml705fl_info->register_base = 0;
	xtkcml705fl_info->user_data_offset = 10;
	xtkcml705fl_info->option_offset = 0;

	//LOG_INFO("flash size = %d KiB", flash_size_in_kb);

	/* did we assign flash size? */
	assert(flash_size_in_kb != 0xffff);

	bank->base = base_address;
	bank->size = 0x01000000; // 16MB fixed

	/* calculate numbers of pages */
	page_size = 0x20000;
	bank->num_sectors = bank->size / page_size;

	/* check that calculation result makes sense */
	assert(bank->num_sectors > 0);

	bank->sectors = alloc_block_array(0, page_size, bank->num_sectors);
	if (!bank->sectors)
		return ERROR_FAIL;


	bank->num_prot_blocks = 0;
	//bank->prot_blocks = alloc_block_array(0, stm32x_info->ppage_size * page_size, num_prot_blocks);
	//if (!bank->prot_blocks)
	//	return ERROR_FAIL;

	xtkcml705fl_info->probed = true;
	return ERROR_OK;
}

static int xtkcml705fl_auto_probe(struct flash_bank *bank)
{
	struct xtkcml705fl_flash_bank *xtkcml705fl_info = bank->driver_priv;
	if (xtkcml705fl_info->probed)
		return ERROR_OK;
	return xtkcml705fl_probe(bank);
}

static int xtkcml705fl_erase_sector(struct flash_bank *bank, int sector)
{
	unsigned int flashpos = FLASHADDR + sector * BLOCKSIZE;
	unsigned char stat;

	flashwrite(bank, FLASHADDR, 0x50);		/* clear status register */
	/* unlock block */
	flashwrite(bank, flashpos, 0x60);		/*   clear block lock bits */
	flashwrite(bank, flashpos, 0xD0);		/*   clear block lock confirm */
	while (((stat = flashread(bank, FLASHADDR)) & 0x80) == 0)
		;
	if (stat & ~0x80) {
		LOG_ERROR("Unlock flash block %d (0x%x) failed: %d", sector, flashpos, stat);
		return ERROR_FLASH_OPERATION_FAILED;
	}
	/* erase block */
	flashwrite(bank, flashpos, 0x20);		/*   block erase mode */
	flashwrite(bank, flashpos, 0xD0);		/*   block erase confirm */
	while (((stat = flashread(bank, FLASHADDR)) & 0x80) == 0)
		;
	if (stat & ~0x80) {
		LOG_ERROR("Erase flash block %d (0x%x) failed: %d", sector, flashpos, stat);
		return ERROR_FLASH_OPERATION_FAILED;
	}
	flashwrite(bank, FLASHADDR, 0xFF);		/* restore read array (normal) mode */
	return ERROR_OK;
}

static int xtkcml705fl_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{
	int retval;

	/*
	 * It could be possible to do a mass erase if all sectors must be
	 * erased, but it is not implemented yet.
	 */

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/*
	 * Loop over the selected sectors and erase them
	 */
	for (unsigned int i = first; i <= last; i++) {
		retval = xtkcml705fl_erase_sector(bank, i);
		if (retval != ERROR_OK)
			return retval;
		bank->sectors[i].is_erased = 1;
	}
	return ERROR_OK;
}

static int xtkcml705fl_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t address, uint32_t count)
{
	struct target *target = bank->target;
	uint32_t buffer_size;
	struct working_area *write_algorithm;
	struct working_area *source;
	struct xtensa_algorithm xtensa_info;
	uint32_t hwords_count = count / 2;
	int retval;

	// TODO: Xtensa stub loader....
	static const uint8_t xtkcml705fl_flash_write_code[] = {
#include "../../../contrib/loaders/flash/xtensa/xtkcml705fl.inc"
	};

	/* The flash write must be aligned to a halfword boundary.
	 * The flash infrastructure ensures it, do just a security check
	 */
	assert(address % 2 == 0);
	assert(count % 2 == 0);

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* flash write code */
	if (target_alloc_working_area(target, sizeof(xtkcml705fl_flash_write_code),
			&write_algorithm) != ERROR_OK) {
		LOG_WARNING("no working area available, can't do block memory writes");
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	retval = target_write_buffer(target, write_algorithm->address,
			sizeof(xtkcml705fl_flash_write_code), xtkcml705fl_flash_write_code);
	if (retval != ERROR_OK) {
		target_free_working_area(target, write_algorithm);
		return retval;
	}

	/* memory buffer */
	buffer_size = target_get_working_area_avail(target);
	buffer_size = MIN(hwords_count * 2 + 8, MAX(buffer_size, 256));
	/* Normally we allocate all available working area.
	 * MIN shrinks buffer_size if the size of the written block is smaller.
	 * MAX prevents using async algo if the available working area is smaller
	 * than 256, the following allocation fails with
	 * ERROR_TARGET_RESOURCE_NOT_AVAILABLE and slow flashing takes place.
	 */

	retval = target_alloc_working_area(target, buffer_size, &source);
	/* Allocated size is always 32-bit word aligned */
	if (retval != ERROR_OK) {
		target_free_working_area(target, write_algorithm);
		LOG_WARNING("no large enough working area available, can't do block memory writes");
		/* target_alloc_working_area() may return ERROR_FAIL if area backup fails:
		 * convert any error to ERROR_TARGET_RESOURCE_NOT_AVAILABLE
		 */
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	/* data to program */
	retval = target_write_buffer(target, source->address, source->size, buffer);
	if (retval != ERROR_OK) {
		target_free_working_area(target, source);
		target_free_working_area(target, write_algorithm);
		return retval;
	}

	struct reg_param reg_params[5];

	// TODO: FIXME: ARs appropriate for both windowed/call0 configs?
	init_reg_param(&reg_params[0], "a10", 32, PARAM_IN_OUT);	/* flash base (in), status (out) */
	init_reg_param(&reg_params[1], "a11", 32, PARAM_OUT);		/* count (halfword-16bit) */
	init_reg_param(&reg_params[2], "a12", 32, PARAM_OUT);		/* buffer start */
	init_reg_param(&reg_params[3], "a13", 32, PARAM_OUT);		/* buffer end */
	init_reg_param(&reg_params[4], "a14", 32, PARAM_IN_OUT);	/* target address */

	buf_set_u32(reg_params[0].value, 0, 32, FLASHADDR);
	buf_set_u32(reg_params[1].value, 0, 32, hwords_count);
	buf_set_u32(reg_params[2].value, 0, 32, source->address);
	buf_set_u32(reg_params[3].value, 0, 32, source->address + source->size);
	buf_set_u32(reg_params[4].value, 0, 32, FLASHADDR + address);

	xtensa_info.core_mode = XT_MODE_RING0;

	retval = target_run_algorithm(target,
			0, NULL,
			ARRAY_SIZE(reg_params), reg_params,
			write_algorithm->address, 0,
			0, &xtensa_info);

	if (retval == ERROR_FLASH_OPERATION_FAILED)
		LOG_ERROR("flash write failed just before address 0x%" PRIx32,
			buf_get_u32(reg_params[4].value, 0, 32));

	for (unsigned int i = 0; i < ARRAY_SIZE(reg_params); i++)
		destroy_reg_param(&reg_params[i]);

	target_free_working_area(target, source);
	target_free_working_area(target, write_algorithm);

	return retval;
}


static const struct command_registration xtkcml705fl_exec_command_handlers[] = {
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration xtkcml705fl_command_handlers[] = {
	{
		.name = "xtkcml705fl",
		.mode = COMMAND_ANY,
		.help = "xtkcml705fl flash command group",
		.usage = "",
		.chain = xtkcml705fl_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

const struct flash_driver xtkcml705fl_flash = {
	.name = "xtkcml705fl",
	.commands = xtkcml705fl_command_handlers,
	.flash_bank_command = xtkcml705fl_flash_bank_command,
	.erase = xtkcml705fl_erase,
	.protect = NULL,
	.write = xtkcml705fl_write,
	.read = default_flash_read,
	.probe = xtkcml705fl_probe,
	.auto_probe = xtkcml705fl_auto_probe,
	.erase_check = NULL,
	.protect_check = NULL,
	.info = NULL,
	.free_driver_priv = NULL,
};
