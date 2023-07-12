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
