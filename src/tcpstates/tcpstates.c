// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <arpa/inet.h>
#include "btf_helpers.h"
#include "compat.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
#include "trace_helpers.h"

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.emit_timestamp = true;
		break;
	case '4':
		env.target_family = AF_INET;
		break;
	case '6':
		env.target_family = AF_INET6;
		break;
	case 'w':
		env.wide_output = true;
		break;
	case 'L':
	case 'R':
	{
		char *port = strtok(arg, ",");
		while (port) {
			safe_strtol(arg, 1, 65535, state);
			port = strtok(NULL, ",");
		}
		if (key == 'L')
			env.target_sports = strdup(arg);
		else
			env.target_dports = strdup(arg);
		break;
	}
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct tcpstates_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	return err != 0;
}

