// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "biopattern.h"
#include "biopattern.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static struct env {
	char *disk;
	time_t interval;
	bool timestamp;
	bool verbose;
	int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "biopattern 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Show block device I/O pattern.\n"
"\n"
"USAGE: biopattern [--help] [-T] [-d DISK] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    biopattern              # show block I/O pattern\n"
"    biopattern 1 10         # print 1 second summaries, 10 times\n"
"    biopattern -T 1         # 1s summaries with timestamps\n"
"    biopattern -d sdc       # trace sdc only\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "disk", 'd', "DISK", 0, "Trace this disk only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static void parse_positional_arg(const char *arg, int pos,
				 struct argp_state *state)
{
	long value;

	if (pos > 1) {
		warning("Unrecognized positional argument: %s\n", arg);
		argp_usage(state);
	}

	errno = 0;
	value = strtol(arg, NULL, 10);
	if (errno || value <= 0) {
		warning("Invalid %s\n", pos == 0 ? "interval" : "times");
		argp_usage(state);
	}

	if (pos == 0)
		env.interval = value;
	else
		env.times = value;
}

static void parse_arg_extra(void)
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
			if (strlen(arg) + 1 > DISK_NAME_LEN) {
				warning("Invalid disk name: too long\n");
				argp_usage(state);
			}
			env.disk = arg;
			break;
		case 'T':
			env.timestamp = true;
			break;
		case ARGP_KEY_ARG:
			parse_positional_arg(arg, pos_args++, state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
		}
		return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	parse_arg_extra();
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level != LIBBPF_DEBUG || env.verbose)
		return vfprintf(stderr, format, args);
	return 0;
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void print_counter(__u32 dev, const struct counter *counter,
			  struct partitions *partitions)
{
	const struct partition *partition;
	__u32 total = counter->sequential + counter->random;

	if (!total)
		return;

	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-9s ", ts);
	}

	partition = partitions__get_by_dev(partitions, dev);
	printf("%-7s %5ld %5ld %8d %10lld\n",
	       partition ? partition->name : "Unknown",
	       counter->random * 100L / total,
	       counter->sequential * 100L / total, total,
	       counter->bytes / 1024);
}

static void print_map_extra(void)
{
		__u32 lookup_key = -1, next_key;
		int err, fd = bpf_map__fd(counters);
		struct counter counter;
		while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
			err = bpf_map_lookup_elem(fd, &next_key, &counter);
			if (err < 0) {
				warning("Failed to lookup counters: %d\n", err);
				return -1;
			}
			print_counter(next_key, &counter, partitions);
			lookup_key = next_key;
		}
		lookup_key = -1;
		while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
			err = bpf_map_delete_elem(fd, &next_key);
			if (err < 0) {
				warning("Failed to cleanup counters: %d\n", err);
				return -1;
			}
			lookup_key = next_key;
		}
		return 0;
}

static int print_map(struct bpf_map *counters, struct partitions *partitions)
{
	print_map_extra();
}

static bool setup_disk_filter(struct biopattern_bpf *obj,
			      const struct partitions *partitions)
{
	const struct partition *partition;

	if (!env.disk)
		return true;

	partition = partitions__get_by_name(partitions, env.disk);
	if (!partition) {
		warning("Invalid partition name: %s not exist\n", env.disk);
		return false;
	}
	obj->rodata->filter_dev = true;
	obj->rodata->target_dev = partition->dev;
	return true;
}

static void print_header(void)
{
	if (env.timestamp)
		printf("%-9s ", "TIME");
	printf("%-7s %5s %5s %8s %10s\n", "DISK", "%RND", "%SEQ", "COUNT", "KBYTES");
}

static void main_extra(void)
{
		LIBBPF_OPTS(bpf_object_open_opts, open_opts);
		struct partitions *partitions = NULL;
		static struct argp argp = {
			.options = opts,
			.parser = parse_arg,
			.doc = argp_program_doc,
		};
		struct biopattern_bpf *obj;
		int err;
		err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
		if (err)
			return err;
		if (!bpf_is_root())
			return 1;
		libbpf_set_print(libbpf_print_fn);
		err = ensure_core_btf(&open_opts);
		if (err) {
			warning("Failed to fetch necessary BTF for CO-RE: %s\n",
				strerror(-err));
			return 1;
		}
		obj = biopattern_bpf__open_opts(&open_opts);
		if (!obj) {
			warning("Failed to open BPF object\n");
			return 1;
		}
		partitions = partitions__load();
		if (!partitions) {
			warning("Failed to load partitions info\n");
			goto cleanup;
		}
		if (!setup_disk_filter(obj, partitions))
			goto cleanup;
		err = biopattern_bpf__load(obj);
		if (err) {
			warning("Failed to load BPF object: %d\n", err);
			goto cleanup;
		}
		err = biopattern_bpf__attach(obj);
		if (err) {
			warning("Failed to attach BPF programs\n");
			goto cleanup;
		}
		signal(SIGINT, sig_handler);
		printf("Tracing block device I/O requested seeks... Hit Ctrl-C to end.\n");
		print_header();
		while (1) {
			sleep(env.interval);
			err = print_map(obj->maps.counters, partitions);
			if (err)
				break;
			if (exiting || --env.times == 0)
				break;
		}
	cleanup:
		biopattern_bpf__destroy(obj);
		partitions__free(partitions);
		cleanup_core_btf(&open_opts);
		return err != 0;
}

int main(int argc, char *argv[])
{
	main_extra();
}
