// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "tcppktlat.h"
#include "tcppktlat.skel.h"
#include "compat.h"
#include "trace_helpers.h"

#include <arpa/inet.h>

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "tid", 't', "TID", 0, "Thread ID to trace" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "lport", 'l', "LPORT", 0, "Filter for local port" },
	{ "rport", 'r', "RPORT", 0, "Filter for remote port" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "print-addr-width", 'W', "ADDR-WIDTH", 0, "Specify print width of tcp address (default 15)" },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 skb only" },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 skb only" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		env.tid = argp_parse_pid(key, arg, state);
		break;
	case 'l':
		env.lport = argp_parse_long(key, arg, state);
		break;
	case 'r':
		env.rport = argp_parse_long(key, arg, state);
		break;
	case 'W':
		env.column_width = argp_parse_long(key, arg, state);
		break;
	case '4':
		env.target_family = AF_INET;
		break;
	case '6':
		env.target_family = AF_INET6;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.min_us = argp_parse_long(key, arg, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	return 0
}
