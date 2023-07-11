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

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'd':
		env.duration = argp_parse_long(key, arg, state);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		env.lport = htons(argp_parse_long(key, arg, state));
		break;
	case 'P':
		env.rport = htons(argp_parse_long(key, arg, state));
		break;
	case 'a':
	case 'A':
	{
		struct in_addr addr;

		if (inet_aton(arg, &addr) < 0) {
			warning("Invalid address: %s\n", arg);
			argp_usage(state);
		}
		if (key == 'a')
			env.laddr = addr.s_addr;
		else
			env.raddr = addr.s_addr;
		break;
	}
	case 'b':
		env.laddr_hist = true;
		break;
	case 'B':
		env.raddr_hist = true;
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

static void sig_handler(int sig)
{
	exiting = 1;
}