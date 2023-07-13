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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
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

        if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

        err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}
        
	obj = tcpstates_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = 1;
		goto cleanup;
	}
        
	obj->rodata->filter_by_sport = env.target_sports != NULL;
	obj->rodata->filter_by_dport = env.target_dports != NULL;
	obj->rodata->target_family = env.target_family;

	if (probe_tp_btf("inet_sock_set_state"))
		bpf_program__set_autoload(obj->progs.inet_sock_set_state_raw, false);
	else
		bpf_program__set_autoload(obj->progs.inet_sock_set_state, false);

	return err != 0;
}

