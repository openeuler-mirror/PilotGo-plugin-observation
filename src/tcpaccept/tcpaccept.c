// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpaccept.py - 2015 Brendan Gregg

#include "commons.h"
#include "tcpaccept.h"
#include "tcpaccept.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"
#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcpaccept 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\nTrace TCP accepts\n"
"\n"
"EXAMPLES:\n"
"    tcpaccept             # trace all TCP accepts\n"
"    tcpaccept -t          # include timestamps\n"
"    tcpaccept -p 181      # only trace PID 181\n"
"    tcpaccept -P 80,81    # only trace port 80 and 81\n"
"    tcpaccept -4          # trace IPv4 family only\n"
"    tcpaccept -6          # trace IPv6 family only\n"
;

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "include time column on output (HH:MM:SS)" },
	{ "timestamp", 't', NULL, 0, "include timestamp on output" },
	{ "pid", 'p', "PID", 0, "trace this PID only" },
	{ "port", 'P', "PORTS", 0, "comma-separated list of local ports to trace" },
	{ "ipv4", '4', NULL, 0, "trace IPv4 family only" },
	{ "ipv6", '6', NULL, 0, "trace IPv6 family only" },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show this help message and exit" },
	{}
};

static struct env {
	bool time;
	bool timestamp;
	bool pid;
	pid_t trace_pid;
	bool port;
	char *target_ports;
	bool ipv4_only;
	bool ipv6_only;
} env;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *port;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'T':
		env.time = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'p':
		env.trace_pid = argp_parse_pid(key, arg, state);
		env.pid = true;
		break;
	case 'P':
		env.port = true;
		if (!arg) {
			warning("No ports specified\n");
			argp_usage(state);
		}
		env.target_ports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			int port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warning("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case '4':
		env.ipv4_only = true;
		break;
	case '6':
		env.ipv6_only = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void print_header(void)
{
	if (env.time)
		printf("%-9s", "TIME");

	if (env.timestamp)
		printf("%-9s", "TIME(s)");

	printf("%-7s %-12s %-2s %-16s %-5s %-16s %-5s",
	       "PID", "COMM", "IP", "RADDR", "RPORT", "LADDR", "LPORT");
	printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	char time_now[16];
	const struct data_t *event = data;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (env.ipv4_only && event->af == AF_INET6)
		return 0;

	if (env.ipv6_only && event->af == AF_INET)
		return 0;

	if (event->af == AF_INET) {
		s.x4.s_addr = event->saddr_v4;
		d.x4.s_addr = event->daddr_v4;
	} else if (event->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, event->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, event->daddr_v6, sizeof(d.x6.s6_addr));
	}

	if (env.time) {
		strftime_now(time_now, sizeof(time_now), "%H:%M:%S");
		printf("%-8s ", time_now);
	}

	if (env.timestamp)
		printf("%-8.3f ", time_since_start());

	printf("%-7d %-12.12s %-2lld %-16s %-5d %-16s %-5d\n",
	       event->pid,
	       event->task,
	       event->ip,
	       inet_ntop(event->af, &d, dst, sizeof(dst)),
	       ntohs(event->dport),
	       inet_ntop(event->af, &s, src, sizeof(src)),
	       event->lport);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int print_events(struct bpf_buffer *buf)
{
	int err;

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		return err;
	}

	print_header();

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n",
				strerror(-err));
			break;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	return err;
}