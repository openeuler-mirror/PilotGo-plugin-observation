// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpretrans.py - Brendan Gregg and Matthias Tafelmeier

#include "commons.h"
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"
#include <arpa/inet.h>

#define INET_ADDRPORTSTRLEN		INET_ADDRSTRLEN + 6
#define INET6_ADDRPORTSTRLEN		INET6_ADDRSTRLEN + 6

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcpretrans 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\ntcpretrans: Trace TCP retransmits\n"
"\n"
"EXAMPLES:\n"
"    tcpretrans             # trace TCP retransmits\n"
"    tcpretrans -l          # include TLP attempts\n"
"    tcpretrans -4          # trace IPv4 family only\n"
"    tcpretrans -6          # trace IPv6 family only\n"
;

const char *tcp_state[] = {
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
};

const char *tcp_type[] = {
	[1] = "R",
	[2] = "L",
};