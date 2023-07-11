// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "tcprtt.h"
#include "tcprtt.skel.h"
#include "trace_helpers.h"
#include <arpa/inet.h>

static struct env {
	__u16 lport;
	__u16 rport;
	__u32 laddr;
	__u32 raddr;
	bool milliseconds;
	time_t duration;
	time_t interval;
	bool timestamp;
	bool laddr_hist;
	bool raddr_hist;
	bool extended;
	bool verbose;
} env = {
	.interval = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcprtt 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize TCP RTT as a histogram.\n"
"\n"
"USAGE: \n"
"\n"
"EXAMPLES:\n"
"    tcprtt            # summarize TCP RTT\n"
"    tcprtt -i 1 -d 10 # print 1 second summaries, 10 times\n"
"    tcprtt -m -T      # summarize in millisecond, and timestamps\n"
"    tcprtt -p         # filter for local port\n"
"    tcprtt -P         # filter for remote port\n"
"    tcprtt -a         # filter for local address\n"
"    tcprtt -A         # filter for remote address\n"
"    tcprtt -b         # show sockets histogram by local address\n"
"    tcprtt -B         # show sockets histogram by remote address\n"
"    tcprtt -e         # show extension summary(average)\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "INTERVAL", 0, "summary interval, seconds" },
	{ "duration", 'd', "DURATION", 0, "total duration of trace, seconds" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "millisecond", 'm', NULL, 0, "millisecond histogram" },
	{ "lport", 'p', "LPORT", 0, "filter for local port" },
	{ "rport", 'P', "RPORT", 0, "filter for remote port" },
	{ "laddr", 'a', "LADDR", 0, "filter for local address" },
	{ "raddr", 'A', "RADDR", 0, "filter for remote address" },
	{ "byladdr", 'b', NULL, 0,
	  "show sockets histogram by local address" },
	{ "byraddr", 'B', NULL, 0,
	  "show sockets histogram by remote address" },
	{ "extension", 'e', NULL, 0, "show extension summary(average)" },
	{ "verbose", 'v', NULL, 0, "verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};