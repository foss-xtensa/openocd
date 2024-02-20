/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Copyright (C) 2016-2017 by Marc Schink <dev@zapb.de>
 * Copyright (C) 2023 by Cadence Design Systems, Inc.
 */

#ifndef OPENOCD_SERVER_TRAX_SERVER_H
#define OPENOCD_SERVER_TRAX_SERVER_H

#include <helper/command.h>

int trax_server_register_commands(struct command_context *ctx);

#endif /* OPENOCD_SERVER_TRAX_SERVER_H */
