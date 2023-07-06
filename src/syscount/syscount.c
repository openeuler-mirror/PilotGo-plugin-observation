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
static int compare_latency(const void *dx, const void *dy)
{
	__u64 x = ((struct data_ext_t *)dx)->total_ns;
	__u64 y = ((struct data_ext_t *)dy)->total_ns;

	return x > y ? -1 : !(x == y);
}

static const char *agg_col(struct data_ext_t *val, char *buf, size_t size)
{
	if (env.process) {
		snprintf(buf, size, "%-6u %-15s", val->key, val->comm);
	} else {
		syscall_name(val->key, buf, size);
	}
	return buf;
}

static const char *agg_colname(void)
{
	return (env.process) ? "PID    COMM" : "SYSCALL";
}

static const char *time_colname(void)
{
	return (env.milliseconds) ? "TIME(ms)" : "TIME(us)";
}

static void print_latency_header(void)
{
	printf("%-22s %8s %16s\n", agg_colname(), "COUNT", time_colname());
}

static void print_count_header(void)
{
	printf("%-22s %8s\n", agg_colname(), "COUNT");
}

static void print_latency(struct data_ext_t *vals, size_t count)
{
	double div = env.milliseconds ? 1000000.0 : 1000.0;
	char buf[2 * TASK_COMM_LEN];

	print_latency_header();
	for (int i = 0; i < count && i < env.top; i++) {
		printf("%-22s %8llu %16.3lf\n",
		       agg_col(&vals[i], buf, sizeof(buf)),
		       vals[i].count, vals[i].total_ns / div);
	}
	printf("\n");
}

static void print_count(struct data_ext_t *vals, size_t count)
{
	char buf[2 * TASK_COMM_LEN];

	print_count_header();
	for (int i = 0; i < count && i < env.top; i++)
		printf("%-22s %8llu\n",
		       agg_col(&vals[i], buf, sizeof(buf)), vals[i].count);
	printf("\n");
}

static void print_timestamp(void)
{
	time_t now = time(NULL);
	struct tm tm;

	if (localtime_r(&now, &tm))
		printf("[%02d:%02d:%02d]\n", tm.tm_hour, tm.tm_min, tm.tm_sec);
	else
		warning("localtime_r: %s", strerror(errno));
}

static bool batch_map_ops = true; /* hope for the best */

static bool read_vals_batch(int fd, struct data_ext_t *vals, __u32 *count)
{
	struct data_t orig_vals[*count];
	void *in = NULL, *out;
	__u32 i, n, n_read = 0;
	__u32 keys[*count];
	int err = 0;

	while (n_read < *count && !err) {
		n = *count - n_read;
		err = bpf_map_lookup_and_delete_batch(fd, &in, &out,
				keys + n_read, orig_vals + n_read, &n, NULL);
		if (err && errno != ENOENT) {
			/* we want to propagate EINVAL upper, so that
			 * the batch_map_ops flag is set to false */
			if (errno != EINVAL)
				warning("bpf_map_lookup_and_delete_batch: %s\n",
					strerror(-err));
			return false;
		}
		n_read += n;
		in = out;
	}

	for (i = 0; i < n_read; i++) {
		vals[i].count = orig_vals[i].count;
		vals[i].total_ns = orig_vals[i].total_ns;
		vals[i].key = keys[i];
		strncpy(vals[i].comm, orig_vals[i].comm, TASK_COMM_LEN);
	}

	*count = n_read;
	return true;
}

static bool read_vals(int fd, struct data_ext_t *vals, __u32 *count)
{
	__u32 keys[MAX_ENTRIES];
	struct data_t val;
	__u32 key = -1;
	__u32 next_key;
	int i = 0, j;
	int err;

	if (batch_map_ops) {
		bool ok = read_vals_batch(fd, vals, count);
		if (!ok && errno == EINVAL) {
			/* fallback to a racy variant */
			batch_map_ops = false;
		} else {
			return ok;
		}
	}

	if (!vals || !count || !*count)
		return true;

	for (key = -1; i < *count; ) {
		err = bpf_map_get_next_key(fd, &key, &next_key);
		if (err && errno != ENOENT) {
			warning("Failed to get next key: %s\n", strerror(errno));
			return false;
		} else if (err) {
			break;
		}
		key = keys[i++] = next_key;
	}

	for (j = 0; j < i; j++) {
		err = bpf_map_lookup_elem(fd, &keys[j], &val);
		if (err && errno != ENOENT) {
			warning("Failed to lookup element: %s\n", strerror(errno));
			return false;
		}
		vals[j].count = val.count;
		vals[j].total_ns = val.total_ns;
		vals[j].key = keys[j];
		memcpy(vals[j].comm, val.comm, TASK_COMM_LEN);
	}

	/* There is a race here: system calls which are represented by keys
	 * above and happended between lookup and delete will be ignored. This
	 * will be fixed in future by using bpf_map_lookup_and_delete_batch,
	 * but this function is too fresh to use it in bcc. */
	for (j = 0; j < i; j++) {
		err = bpf_map_delete_elem(fd, &keys[j]);
		if (err) {
			warning("failed to delete element: %s\n", strerror(errno));
			return false;
		}
	}

	*count = i;
	return true;
}
