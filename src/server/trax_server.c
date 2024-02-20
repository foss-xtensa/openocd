// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2016-2017 by Marc Schink <dev@zapb.de>
 * Copyright (C) 2023 by Cadence Design Systems, Inc.
 *
 * Based on RTT server.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <trax/trax.h>

#include "server.h"
#include "trax_server.h"

/**
 * @file
 *
 * TRAX server.
 *
 * This server allows access to TRAX channels via TCP connections.
 */

struct trax_service {
	unsigned int channel;
};

static int trax_new_connection(struct connection *connection)
{
	int ret;
	struct trax_service *service;

	service = connection->service->priv;

	LOG_DEBUG("trax server: New connection for channel %u", service->channel);

	ret = trax_register_sink(service->channel, connection);

	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int trax_connection_closed(struct connection *connection)
{
	struct trax_service *service;

	service = (struct trax_service *)connection->service->priv;
	trax_unregister_sink(service->channel, connection);

	LOG_DEBUG("trax server: Connection for channel %u closed", service->channel);

	return ERROR_OK;
}

static int trax_input(struct connection *connection)
{
	int bytes_read, ret;
	unsigned char buffer[1024];
	struct trax_service *service;
	size_t length;

	service = (struct trax_service *)connection->service->priv;
	bytes_read = connection_read(connection, buffer, sizeof(buffer));

	if (!bytes_read) {
		return ERROR_SERVER_REMOTE_CLOSED;
	} else if (bytes_read < 0) {
		LOG_ERROR("error during read: %s", strerror(errno));
		return ERROR_SERVER_REMOTE_CLOSED;
	}

	length = bytes_read;
	ret = trax_write_channel(service->channel, buffer, &length);
	if (ret > 0) {
		int *ibuf = (int *)buffer;

		LOG_DEBUG("trax server: Sending %lu byte response (0x%08x 0x%08x 0x%08x 0x%08x 0x%08x)",
			length, ibuf[0], ibuf[1], ibuf[2], ibuf[3], ibuf[4]);
		ret = connection_write(connection, buffer, length);

		if (ret < 0) {
			LOG_ERROR("Failed to write data to socket.");
			return ERROR_FAIL;
		}
	}

	return (ret < 0) ? ERROR_FAIL : ERROR_OK;
}

static const struct service_driver trax_service_driver = {
	.name = "trax",
	.new_connection_during_keep_alive_handler = NULL,
	.new_connection_handler = trax_new_connection,
	.input_handler = trax_input,
	.connection_closed_handler = trax_connection_closed,
	.keep_client_alive_handler = NULL,
};

COMMAND_HANDLER(handle_trax_start_command)
{
	int ret;
	struct trax_service *service;

	if (CMD_ARGC != 2)
		return ERROR_COMMAND_SYNTAX_ERROR;

	service = malloc(sizeof(struct trax_service));

	if (!service)
		return ERROR_FAIL;

	COMMAND_PARSE_NUMBER(uint, CMD_ARGV[1], service->channel);

	ret = add_service(&trax_service_driver, CMD_ARGV[0], CONNECTION_LIMIT_UNLIMITED, service);

	if (ret != ERROR_OK) {
		free(service);
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(handle_trax_stop_command)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	remove_service("trax", CMD_ARGV[0]);

	return ERROR_OK;
}

static const struct command_registration trax_server_subcommand_handlers[] = {
	{
		.name = "start",
		.handler = handle_trax_start_command,
		.mode = COMMAND_ANY,
		.help = "Start a TRAX server",
		.usage = "<port> <channel>"
	},
	{
		.name = "stop",
		.handler = handle_trax_stop_command,
		.mode = COMMAND_ANY,
		.help = "Stop a TRAX server",
		.usage = "<port>"
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration trax_server_command_handlers[] = {
	{
		.name = "server",
		.mode = COMMAND_ANY,
		.help = "TRAX server",
		.usage = "",
		.chain = trax_server_subcommand_handlers
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration trax_command_handlers[] = {
	{
		.name = "trax",
		.mode = COMMAND_ANY,
		.help = "TRAX",
		.usage = "",
		.chain = trax_server_command_handlers
	},
	COMMAND_REGISTRATION_DONE
};

int trax_server_register_commands(struct command_context *ctx)
{
	return register_commands(ctx, NULL, trax_command_handlers);
}
