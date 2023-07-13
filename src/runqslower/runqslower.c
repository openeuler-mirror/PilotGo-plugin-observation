// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "runqslower.h"
#include "runqslower.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	bool previous;
	bool verbose;
} env = {
	.min_us = 1000,
};

const char *argp_program_version = "runqslower 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace high run queue latency.\n"
"\n"
"USAGE: runqslower [--help] [-p PID] [-t tid] [-P] [min_us]\n"
"\n"
"EXAMPLES:\n"
"  runqslower         # trace latency higher than 10000 us (default)\n"
"  runqslower 1000    # trace latency higher than 1000 us\n"
"  runqslower -p 123  # trace pid 123 only\n"
"  runqslower -t 123  # trace tid 123 (use for threads only)\n"
"  runqslower -P      # also show previous task name and TID\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "tid", 't', "TID", 0, "Thread ID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "previous", 'P', NULL, 0, "also show previous task name and TID" },
	{ "NULL", 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_args(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;
	long long min_us;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'P':
		env.previous = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warning("Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			warning("Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct runq_event *e = data;
	char ts[32];

	strftime_now(ts, sizeof(ts), "%H:%M:%S");
	if (env.previous)
		printf("%-8s %-16s %-6d %-14llu %-16s %-6d\n", ts, e->task, e->pid, e->delta_us, e->prev_task, e->prev_pid);
	else
		printf("%-8s %-16s %-6d %-14llu\n", ts, e->task, e->pid, e->delta_us);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}