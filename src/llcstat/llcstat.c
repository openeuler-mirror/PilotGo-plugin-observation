// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include "llcstat.h"
#include "llcstat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

struct env {
	int sample_period;
	time_t duration;
	bool verbose;
	bool per_thread;
} env = {
	.sample_period = 100,
	.duration = 10,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "llcstat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize cache references and misses by PID.\n"
"\n"
"USAGE: llcstat [--help] [-c SAMPLE_PERIOD] [duration]\n";

static const struct argp_option opts[] = {
	{ "sample_period", 'c', "SAMPLE_PERIOD", 0, "Sample one in this many "
	  "number of cache reference / miss events" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "tid", 't', NULL, 0,
	  "Summarize cacge references and misses by PID/TTID" },
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
	case 't':
		env.per_thread = true;
		break;
	case 'c':
		errno = 0;
		env.sample_period = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid sample period");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			warning("Invalid duration");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(__u64 config, int period,
				      struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.freq = 0,
		.sample_period = period,
		.config = config
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			warning("Failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			warning("Failed to attach perf event on CPU: %d\n", i);
			close(fd);
			return -1;
		}
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

static void print_map(struct bpf_map *map)
{
	__u64 total_ref = 0, total_miss = 0, total_hit, hit;
	__u32 pid, cpu, tid;
	struct key_info lookup_key = { .cpu = -1 }, next_key;
	int err, fd = bpf_map__fd(map);
	struct value_info info;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			warning("Failed to lookup infos: %d\n", err);
			return;
		}
		hit = MAX((long)(info.ref - info.miss), 0);
		cpu = next_key.cpu;
		pid = next_key.pid;
		tid = next_key.tid;
		printf("%-8u ", pid);
		if (env.per_thread) {
			printf("%-8u ", tid);
		}
		printf("%-16s %-4u %12llu %12llu %6.2f%%\n",
		       info.comm, cpu, info.ref, info.miss,
		       info.ref > 0 ? hit * 1.0 / info.ref * 100 : 0);
		total_miss += info.miss;
		total_ref += info.ref;
		lookup_key = next_key;
	}

	total_hit = MAX((long)(total_ref - total_miss), 0);
	printf("Total References: %llu Total Misses: %llu Hit Rate: %.2f%%\n",
	       total_ref, total_miss, total_ref > 0 ?
	       total_hit * 1.0 / total_ref * 100 : 0);

	lookup_key.cpu = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err) {
			warning("Failed to cleanup infos: %d\n", err);
			return;
		}
		lookup_key = next_key;
	}
}

