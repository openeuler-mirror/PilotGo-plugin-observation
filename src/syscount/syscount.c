// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "syscount.h"
#include "syscount.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "errno_helpers.h"
#include "syscall_helpers.h"

/*
 * This structure extends data_t by adding a key item which should be sorted
 * together with the count and total_ns fields.
 */
struct data_ext_t {
	__u64 count;
	__u64 total_ns;
	char comm[TASK_COMM_LEN];
	__u32 key;
};

const char *argp_program_version = "syscount 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\nsyscount: summarize syscall counts and latencies\n"
"\n"
"EXAMPLES:\n"
"    syscount                 # print top 10 syscalls by count every second\n"
"    syscount -p $(pidof dd)  # look only at a particular process\n"
"    syscount -L              # measure and sort output by latency\n"
"    syscount -P              # group statistics by pid, not by syscall\n"
"    syscount -x -i 5         # count only failed syscalls\n"
"    syscount -e ENOENT -i 5  # count only syscalls failed with a given errno\n"
"    syscount -c CG           # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "interval", 'i', "INTERVAL", 0,
	  "Print summary at this interval (seconds), 0 for infinite wait (default)" },
	{ "duration", 'd', "DURATION", 0, "Total tracing duration (seconds)" },
	{ "top", 'T', "TOP", 0, "Print only the top syscalls (default 10)" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified/<CG>", 0, "Trace process in cgroup path" },
	{ "failures", 'x', NULL, 0, "Trace only failed syscalls" },
	{ "latency", 'L', NULL, 0, "Collect syscall latency" },
	{ "milliseconds", 'm', NULL, 0, "Display latency in milliseconds"
					" (default: microseconds)" },
	{ "process", 'P', NULL, 0, "Count by process and not by syscall" },
	{ "errno", 'e', "ERRNO", 0, "Trace only syscalls that return this error"
				"(numeric or EPERM, etc.)" },
	{ "list", 'l', NULL, 0, "Print list of recognized syscalls and exit" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static struct env {
	bool list_syscalls;
	bool milliseconds;
	bool failures;
	bool verbose;
	bool latency;
	bool process;
	int filter_errno;
	int interval;
	int duration;
	int top;
	pid_t pid;
	char *cgroupspath;
	bool cg;
} env = {
	.top = 10,
};

static inline __maybe_unused
long argp_parse_long_range(int key, const char *arg, struct argp_state *state,
			   long min, long max)
{
	long temp = argp_parse_long(key, arg, state);
	if (temp > max || temp < min) {
		warning("value isn't in range [%ld - %ld]\n", min, max);
		argp_usage(state);
	}
	return temp;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int compare_count(const void *dx, const void *dy)
{
	__u64 x = ((struct data_ext_t *)dx)->count;
	__u64 y = ((struct data_ext_t *)dy)->count;

	return x > y ? -1 : !(x == y);
}
