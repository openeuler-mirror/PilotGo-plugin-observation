// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <arpa/inet.h>
#include "btf_helpers.h"
#include "compat.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool emit_timestamp;
	short target_family;
	char *target_sports;
	char *target_dports;
	bool wide_output;
	bool verbose;
} env;

static const char *tcp_states[] = {
	[1] = "ESTABLISHED",
	[2] = "SYN_SENT",
	[3] = "SYN_RECV",
	[4] = "FIN_WAIT1",
	[5] = "FIN_WAIT2",
	[6] = "TIME_WAIT",
	[7] = "CLOSE",
	[8] = "CLOSE_WAIT",
	[9] = "LAST_ACK",
	[10] = "LISTEN",
	[11] = "CLOSING",
	[12] = "NEW_SYN_RECV",
	[13] = "UNKNOWN",
};

const char *argp_program_version = "tcpstates 1.0";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace TCP session state changes and durations.\n"
"\n"
"USAGE: tcpstates [-4] [-6] [-T] [-L lport] [-R dport]\n"
"\n"
"EXAMPLES:\n"
"    tcpstates                  # trace all TCP state changes\n"
"    tcpstates -T               # include timestamps\n"
"    tcpstates -L 80            # only trace local port 80\n"
"    tcpstates -D 80            # only trace remote port 80\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family only" },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 family only" },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)" },
	{ "localport", 'L', "LPORT", 0, "Comma-separated list of local ports to trace." },
	{ "remoteport", 'R', "RPORT", 0, "Comma-separated list of remote ports to trace." },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

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

