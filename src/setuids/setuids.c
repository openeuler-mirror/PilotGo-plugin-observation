// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "setuids.h"
#include "setuids.skel.h"
#include "compat.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	bool timestamp;
} env;

const char *argp_program_version = "setuids 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace the setuid syscalls: privilege escalation.\n"
"\n"
"USAGS:    setuids [-v] [-T]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
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
		env.timestamp = true;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (env.timestamp) {
		char ts[16];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
	}

	printf("%-6d %-16s %-6d ", e->pid, e->comm, e->uid);

	switch (e->type) {
	case UID:
		printf("%-9s uid=%d (%d)\n", "setuid", e->setuid, e->ret);
		break;
	case FSUID:
		printf("%-9s uid=%d (prevuid=%d)\n", "setfsuid", e->setuid, e->ret);
		break;
	case REUID:
		printf("%-9s ruid=%d euid=%d suid=%d (%d)\n", "setreuid",
		       e->ruid, e->euid, e->suid, e->ret);
		break;
	default:
		break;
	}

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}
