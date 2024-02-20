// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2019-2020 by Marc Schink <dev@zapb.de>
 * Copyright (C) 2023 by Cadence Design Systems, Inc.
 *
 * Based on RTT server.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/log.h>
#include <target/trax.h>

#include "trax.h"


COMMAND_HANDLER(handle_trax_start_command)
{
	struct trax_source source;

	if (CMD_ARGC > 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	source.attach = &target_trax_attach;
	source.start = &target_trax_start;
	source.stop = &target_trax_stop;
	source.write = &target_trax_write_callback;
	source.dm_readreg = &target_trax_dm_readreg;
	source.dm_writereg = &target_trax_dm_writereg;

	if (trax_setup() != ERROR_OK)
		return ERROR_FAIL;

	trax_register_source(source, get_current_target(CMD_CTX));

	if (!trax_configured()) {
		command_print(CMD, "TRAX is not configured");
		return ERROR_FAIL;
	}

	return trax_start();
}

COMMAND_HANDLER(handle_trax_stop_command)
{
	if (CMD_ARGC > 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	return trax_stop();
}

static const struct command_registration trax_subcommand_handlers[] = {
	{
		.name = "start",
		.handler = handle_trax_start_command,
		.mode = COMMAND_EXEC,
		.help = "start TRAX",
		.usage = ""
	},
	{
		.name = "stop",
		.handler = handle_trax_stop_command,
		.mode = COMMAND_EXEC,
		.help = "stop TRAX",
		.usage = ""
	},
	COMMAND_REGISTRATION_DONE
};

const struct command_registration trax_target_command_handlers[] = {
	{
		.name = "trax",
		.mode = COMMAND_EXEC,
		.help = "TRAX target commands",
		.usage = "",
		.chain = trax_subcommand_handlers
	},
	COMMAND_REGISTRATION_DONE
};
