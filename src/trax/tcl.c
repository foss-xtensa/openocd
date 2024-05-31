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
	unsigned int id = 0;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
	else if (CMD_ARGC == 1)
		id = strtoul(CMD_ARGV[0], NULL, 0);

	source.attach = &target_trax_attach;
	source.start = &target_trax_start;
	source.stop = &target_trax_stop;
	source.write = &target_trax_write_callback;
	source.dm_readreg = &target_trax_dm_readreg;
	source.dm_writereg = &target_trax_dm_writereg;
	return trax_start(id, get_current_target(CMD_CTX), source);
}

COMMAND_HANDLER(handle_trax_stop_command)
{
	unsigned int id = 0;

	if (CMD_ARGC > 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
	else if (CMD_ARGC == 1)
		id = strtoul(CMD_ARGV[0], NULL, 0);

	return trax_stop(id);
}

static const struct command_registration trax_subcommand_handlers[] = {
	{
		.name = "start",
		.handler = handle_trax_start_command,
		.mode = COMMAND_EXEC,
		.help = "start TRAX channel",
		.usage = "[chan_id]"
	},
	{
		.name = "stop",
		.handler = handle_trax_stop_command,
		.mode = COMMAND_EXEC,
		.help = "stop TRAX channel",
		.usage = "[chan_id]"
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
