// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "javagc.skel.h"
#include "javagc.h"
#include "compat.h"

#define BINARY_PATH_SIZE	256

static volatile sig_atomic_t exiting;

static struct env {
	pid_t pid;
	int time;
	bool verbose;
} env = {
	.pid = -1,
	.time = 1000,
};

const char *argp_program_version = "javagc 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Monitor javagc time cost.\n"
"\n"
"USAGE: javagc [--help] [-t GC time] PID\n"
"\n"
"EXAMPLES:\n"
"javagc 185         # trace PID 185\n"
"javagc 185 -t 100  # trace PID 185 java gc time beyond 100us\n";

static const struct argp_option opts[] = {
	{ "time", 't', "TIME", 0, "Java gc time" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
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
	case 't':
		env.time = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.pid = argp_parse_pid(key, arg, state);
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (env.pid == -1) {
			warning("The javagc trace program are required: pid\n");
			argp_usage(state);
		}
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct data_t *e = data;
	char ts[16];

	strftime_now(ts, sizeof(ts), "%H:%M:%S");
	printf("%-8s %-7d %-7d %-7lld\n", ts, e->cpu, e->pid, e->ts / 1000);

	return 0;
}