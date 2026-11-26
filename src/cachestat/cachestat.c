// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "cachestat.skel.h"
#include "trace_helpers.h"

struct argument {
	time_t	interval;
	int	times;
	bool	timestamp;
};

static volatile sig_atomic_t exiting;
static volatile bool verbose = false;

const char *argp_program_version = "cachestat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Count cache kernel function calls.\n"
"\n"
"USAGE: cachestat [--help] [-T] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    cachestat          # shows hits and misses to the file system page cache\n"
"    cachestat -T       # include timestamps\n"
"    cachestat 1 10     # print 1 second summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static void parse_positional_arg(struct argument *argument, const char *arg,
				 int pos, struct argp_state *state)
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
		argument->interval = value;
	else
		argument->times = value;
}

static void parse_arg_extra(void)
{
		static int pos_args;
		struct argument *argument = state->input;
		switch (key) {
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case 'v':
			verbose = true;
			break;
		case 'T':
			argument->timestamp = true;
			break;
		case ARGP_KEY_ARG:
			parse_positional_arg(argument, arg, pos_args++, state);
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
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int get_meminfo(__u64 *buffers, __u64 *cached)
{
	FILE *f;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;
	if (fscanf(f,
		   "MemTotal: %*u kB\n"
		   "MemFree: %*u kB\n"
		   "MemAvailable: %*u kB\n"
		   "Buffers: %llu kB\n"
		   "Cached: %llu kB\n",
		   buffers, cached) != 2) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/*
 * account_page_dirtied was renamed to folio_account_dirtied
 * in kernel commit 203a31516616 ("mm/writeback: Add __folio_mark_dirty()")
 */
static bool setup_dirty_tp(struct cachestat_bpf *obj)
{
	if (tracepoint_exists("writeback", "writeback_dirty_folio"))
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_page,
					  false);
	else if (tracepoint_exists("writeback", "writeback_dirty_page"))
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_folio,
					  false);
	else {
		warning("dirty entry not found in current kernel, please upgrade.\n");
		return false;
	}
	return true;
}

static bool setup_misses_tp(struct cachestat_bpf *obj)
{
	/* misses add tracepoint */
	if (fentry_can_attach("filemap_add_folio", NULL)) {
		int err = bpf_program__set_attach_target(
				obj->progs.fentry_add_to_page_cache_lru, 0,
				"filemap_add_folio");
		if (err) {
			warning("Failed to set attach target\n");
			return false;
		}
	}

	if (fentry_can_attach("add_to_page_cache_lru", NULL) ||
	    fentry_can_attach("filemap_add_folio", NULL)) {
		bpf_program__set_autoload(obj->progs.kprobe_add_to_page_cache_lru,
					  false);
		bpf_program__set_autoload(obj->progs.kprobe_filemap_add_folio,
					  false);
	} else {
		if (kprobe_exists("filemap_add_folio"))
			bpf_program__set_autoload(
				obj->progs.kprobe_add_to_page_cache_lru, false);
		else
			bpf_program__set_autoload(
				obj->progs.kprobe_filemap_add_folio, false);
		bpf_program__set_autoload(obj->progs.fentry_add_to_page_cache_lru,
					  false);
	}
	return true;
}

static void setup_total_tp_extra(void)
{
		/* total add tracepoint */
		if (fentry_can_attach("mark_page_accessed", NULL))
			bpf_program__set_autoload(obj->progs.kprobe_mark_page_accessed,
						  false);
		else
			bpf_program__set_autoload(obj->progs.fentry_mark_page_accessed,
						  false);
		if (fentry_can_attach("mark_buffer_dirty", NULL))
			bpf_program__set_autoload(obj->progs.kprobe_mark_buffer_dirty,
						  false);
		else
			bpf_program__set_autoload(obj->progs.fentry_mark_buffer_dirty,
						  false);
}

static void setup_total_tp(struct cachestat_bpf *obj)
{
	setup_total_tp_extra();
}

static void print_header(bool timestamp)
{
	if (timestamp)
		printf("%-8s ", "TIME");
	printf("%8s %8s %8s %8s %12s %10s\n", "HITS", "MISSES", "DIRTIES",
		"HITRATIO", "BUFFERS_MB", "CACHED_MB");
}

static void print_stats_section5_0(void)
{
	
		/*
		 * If hits are < 0, then its possible misses are overestimated
		 * due to possibly page cache read ahead adding more pages than
		 * needed. In this case just assume misses as total and reset
		 * hits.
		 */
		if (hits < 0) {
			misses = total;
			hits = 0;
		}
		ratio = total > 0 ? hits * 1.0 / total : 0.0;
}

static void print_stats_section5_0(void)
{
		err = get_meminfo(&buffers, &cached);
		if (err) {
			warning("Failed to get meminfo: %d\n", err);
			return err;
		}
}

static int print_stats(struct cachestat_bpf *obj, bool timestamp)
{
	__u64 buffers, cached, mbd;
	__s64 total, misses, hits;
	float ratio;
	int err;

	/* total = total cache accesses without counting dirties */
	total = __atomic_exchange_n(&obj->bss->total, 0, __ATOMIC_RELAXED);
	/* misses = total of add to lru because of read misses */
	misses = __atomic_exchange_n(&obj->bss->misses, 0, __ATOMIC_RELAXED);
	/* mbd = total of mark_buffer_dirty events */
	mbd = __atomic_exchange_n(&obj->bss->mbd, 0, __ATOMIC_RELAXED);

	if (total < 0)
		total = 0;
	if (misses < 0)
		misses = 0;
	hits = total - misses;
	print_stats_section5_0();
	print_stats_section5_0();

	if (timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
	}
	printf("%8lld %8lld %8llu %7.2f%% %12llu %10llu\n",
		hits, misses, mbd, 100 * ratio,
		buffers / 1024, cached / 1024);

	return 0;
}

static void main_extra(void)
{
		static const struct argp argp = {
			.options = opts,
			.parser = parse_arg,
			.doc = argp_program_doc,
		};
		struct argument argument = {
			.interval = -1,
			.times = 99999999,
		};
		struct cachestat_bpf *obj;
		int err;
		err = argp_parse(&argp, argc, argv, 0, NULL, &argument);
		if (err)
			return err;
		if (!bpf_is_root())
			return 1;
		libbpf_set_print(libbpf_print_fn);
		obj = cachestat_bpf__open();
		if (!obj) {
			warning("Failed to open BPF object\n");
			return 1;
		}
		if (!setup_dirty_tp(obj) || !setup_misses_tp(obj))
			goto cleanup;
		setup_total_tp(obj);
		err = cachestat_bpf__load(obj);
		if (err) {
			warning("Failed to load BPF object\n");
			goto cleanup;
		}
		if (!obj->bss) {
			warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
			goto cleanup;
		}
		err = cachestat_bpf__attach(obj);
		if (err) {
			warning("Failed to attach BPF programs\n");
			goto cleanup;
		}
		signal(SIGINT, sig_handler);
		print_header(argument.timestamp);
		while (1) {
			sleep(argument.interval);
			err = print_stats(obj, argument.timestamp);
			if (err)
				goto cleanup;
			if (exiting || --argument.times == 0)
				break;
		}
	cleanup:
		cachestat_bpf__destroy(obj);
		return err != 0;
}

int main(int argc, char *argv[])
{
	main_extra();
}
