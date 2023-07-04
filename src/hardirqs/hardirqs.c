// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "hardirqs.h"
#include "hardirqs.skel.h"
#include "trace_helpers.h"

struct env {
	bool count;
	bool distributed;
	bool nanoseconds;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "hardirqs 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize hard irq event time as histograms.\n"
"\n"
"USAGE: hardirqs [--help] [-T] [-N] [-d] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    hardirqs            # sum hard irq event time\n"
"    hardirqs -d         # show hard irq event time as histograms\n"
"    hardirqs 1 10       # print 1 second summaries, 10 times\n"
"    hardirqs -c CG      # Trace process under cgroupsPath CG\n"
"    hardirqs -NT 1      # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "count", 'C', NULL, 0, "Show event counts instead of timing" },
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.distributed = true;
		break;
	case 'C':
		env.count = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'N':
		env.nanoseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				warning("Invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 0);
			if (errno) {
				warning("Invalid times\n");
				argp_usage(state);
			}
		} else {
			warning("Unrecongnized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int print_map(struct bpf_map *map)
{
	irq_key_t lookup_key = {}, next_key;
	info_t info;
	int fd, err;
	const char *units = env.nanoseconds ? "nsecs" : "usecs";

	if (env.count)
		printf("%-26s %11s\n", "HARDIRQ", "TOTAL_count");
	else if (!env.distributed)
		printf("%-26s %6s%5s\n", "HARDIRQ", "TOTAL_", units);

	fd = bpf_map__fd(map);
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			warning("failed to lookup infos: %d\n", err);
			return -1;
		}
		if (!env.distributed) {
			printf("%-26s %11llu\n", next_key.name, info.count);
		} else {
			printf("hardirq = %s\n", next_key.name);
			print_log2_hist(info.slots, MAX_SLOTS, units);
		}
		lookup_key = next_key;
	}

	memset(&lookup_key, 0, sizeof(lookup_key));

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}