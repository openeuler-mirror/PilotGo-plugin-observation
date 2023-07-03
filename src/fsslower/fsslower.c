// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "fsslower.h"
#include "fsslower.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <libgen.h>

enum fs_type {
	NONE,
	BTRFS,
	EXT4,
	NFS,
	XFS,
};

static struct fs_config {
	const char *fs;
	const char *op_funcs[F_MAX_OP];
} fs_configs[] = {
	[BTRFS] = { "btrfs", {
		[F_READ] = "btrfs_file_read_iter",
		[F_WRITE] = "btrfs_file_write_iter",
		[F_OPEN] = "btrfs_file_open",
		[F_FSYNC] = "btrfs_sync_file",
	}},
	[EXT4] = { "ext4", {
		[F_READ] = "ext4_file_read_iter",
		[F_WRITE] = "ext4_file_write_iter",
		[F_OPEN] = "ext4_file_open",
		[F_FSYNC] = "ext4_sync_file",
	}},
	[NFS] = { "nfs", {
		[F_READ] = "nfs_file_read",
		[F_WRITE] = "nfs_file_write",
		[F_OPEN] = "nfs_file_open",
		[F_FSYNC] = "nfs_file_fsync",
	}},
	[XFS] = { "xfs", {
		[F_READ] = "xfs_file_read_iter",
		[F_WRITE] = "xfs_file_write_iter",
		[F_OPEN] = "xfs_file_open",
		[F_FSYNC] = "xfs_file_fsync",
	}},
};

static char file_op[] = {
	[F_READ] = 'R',
	[F_WRITE] = 'W',
	[F_OPEN] = 'O',
	[F_FSYNC] = 'F',
};

static volatile sig_atomic_t exiting = 0;

/* options */
static enum fs_type fs_type = NONE;
static pid_t target_pid = 0;
static time_t duration = 0;
static __u64 min_lat_ms = 10;
static bool csv = false;
static bool verbose = false;

const char *argp_program_version = "fsslower 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace file system operations slower than a threshold.\n"
"\n"
"Usage: fsslower [-h] [-t FS] [-p PID] [-m MIN] [-d DURATION] [-c]\n"
"\n"
"EXAMPLES:\n"
"    fsslower -t ext4             # trace ext4 operations slower than 10 ms\n"
"    fsslower -t nfs -p 1216      # trace nfs operations with PID 1216 only\n"
"    fsslower -t xfs -c -d 1      # trace xfs operations for 1s with csv output\n";

static const struct argp_option opts[] = {
	{ "csv", 'c', NULL, 0, "Output as csv"},
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "min", 'm', "MIN", 0, "Min latency to trace, in ms (default 10)" },
	{ "type", 't', "Filesystem", 0, "Which filesystem to trace, [btrfs/ext4/nfs/xfs]" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'c':
		csv = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			warning("Invalid Duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		min_lat_ms = strtol(arg, NULL, 10);
		if (errno || min_lat_ms <= 0) {
			warning("Invalid latency (in ms): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		if (!strcmp(arg, "btrfs")) {
			fs_type = BTRFS;
		} else if (!strcmp(arg, "ext4")) {
			fs_type = EXT4;
		} else if (!strcmp(arg, "nfs")) {
			fs_type = NFS;
		} else if (!strcmp(arg, "xfs")) {
			fs_type = XFS;
		} else {
			warning("Invalid filesystem\n");
			argp_usage(state);
		}
		break;
	case 'p':
		target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "btrfsslower"))
		fs_type = BTRFS;
	else if (!strcmp(name, "ext4slower"))
		fs_type = EXT4;
	else if (!strcmp(name, "nfsslower"))
		fs_type = NFS;
	else if (!strcmp(name, "xfsslower"))
		fs_type = XFS;
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

static bool check_fentry()
{
	for (int i = 0; i < F_MAX_OP; i++) {
		const char *fn_name = fs_configs[fs_type].op_funcs[i];
		const char *module = fs_configs[fs_type].fs;

		if (fn_name && !fentry_can_attach(fn_name, module))
			return false;
	}

	return true;
}

static int fentry_set_attach_target(struct bpf_program *prog, enum fs_file_op op)
{
	return bpf_program__set_attach_target(prog, 0, fs_configs[fs_type].op_funcs[op]);
}

static int fentry_set_attach_targets(struct fsslower_bpf *obj)
{
	int err = 0;

	err = fentry_set_attach_target(obj->progs.file_read_fentry, F_READ);
	if (err)
		return err;
	err = fentry_set_attach_target(obj->progs.file_read_fexit, F_READ);
	if (err)
		return err;
	err = fentry_set_attach_target(obj->progs.file_write_fentry, F_WRITE);
	if (err)
		return err;
	err = fentry_set_attach_target(obj->progs.file_write_fexit, F_WRITE);
	if (err)
		return err;
	err = fentry_set_attach_target(obj->progs.file_open_fentry, F_OPEN);
	if (err)
		return err;
	err = fentry_set_attach_target(obj->progs.file_open_fexit, F_OPEN);
	if (err)
		return err;
	err = fentry_set_attach_target(obj->progs.file_sync_fentry, F_FSYNC);
	if (err)
		return err;
	err = fentry_set_attach_target(obj->progs.file_sync_fexit, F_FSYNC);
	if (err)
		return err;

	return 0;
}

static void disable_fentry(struct fsslower_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.file_read_fentry, false);
	bpf_program__set_autoload(obj->progs.file_read_fexit, false);
	bpf_program__set_autoload(obj->progs.file_write_fentry, false);
	bpf_program__set_autoload(obj->progs.file_write_fexit, false);
	bpf_program__set_autoload(obj->progs.file_open_fentry, false);
	bpf_program__set_autoload(obj->progs.file_open_fexit, false);
	bpf_program__set_autoload(obj->progs.file_sync_fentry, false);
	bpf_program__set_autoload(obj->progs.file_sync_fexit, false);
}

static void disable_kprobes(struct fsslower_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.file_read_entry, false);
	bpf_program__set_autoload(obj->progs.file_read_exit, false);
	bpf_program__set_autoload(obj->progs.file_write_entry, false);
	bpf_program__set_autoload(obj->progs.file_write_exit, false);
	bpf_program__set_autoload(obj->progs.file_open_entry, false);
	bpf_program__set_autoload(obj->progs.file_open_exit, false);
	bpf_program__set_autoload(obj->progs.file_sync_entry, false);
	bpf_program__set_autoload(obj->progs.file_sync_exit, false);
}

static int attach_kprobes(struct fsslower_bpf *obj)
{
	obj->links.file_read_entry = bpf_program__attach_kprobe(obj->progs.file_read_entry,
								false,
								fs_configs[fs_type].op_funcs[F_READ]);
	if (!obj->links.file_read_entry)
		goto errout;

	obj->links.file_read_exit = bpf_program__attach_kprobe(obj->progs.file_read_exit,
							       true,
							       fs_configs[fs_type].op_funcs[F_READ]);
	if (!obj->links.file_read_exit)
		goto errout;

	obj->links.file_write_entry = bpf_program__attach_kprobe(obj->progs.file_write_entry,
								 false,
								 fs_configs[fs_type].op_funcs[F_WRITE]);
	if (!obj->links.file_write_entry)
		goto errout;

	obj->links.file_write_exit = bpf_program__attach_kprobe(obj->progs.file_write_exit,
								true,
								fs_configs[fs_type].op_funcs[F_WRITE]);
	if (!obj->links.file_write_exit)
		goto errout;

	obj->links.file_open_entry = bpf_program__attach_kprobe(obj->progs.file_open_entry,
								false,
								fs_configs[fs_type].op_funcs[F_OPEN]);
	if (!obj->links.file_open_entry)
		goto errout;

	obj->links.file_open_exit = bpf_program__attach_kprobe(obj->progs.file_open_exit,
							       true,
							       fs_configs[fs_type].op_funcs[F_OPEN]);
	if (!obj->links.file_open_exit)
		goto errout;

	obj->links.file_sync_entry = bpf_program__attach_kprobe(obj->progs.file_sync_entry,
								false,
								fs_configs[fs_type].op_funcs[F_FSYNC]);
	if (!obj->links.file_sync_entry)
		goto errout;

	obj->links.file_sync_exit = bpf_program__attach_kprobe(obj->progs.file_sync_exit,
							       false,
							       fs_configs[fs_type].op_funcs[F_FSYNC]);
	if (!obj->links.file_sync_exit)
		goto errout;

	return 0;

errout:
	warning("Failed to attach kprobe: %d\n", -errno);
	return -errno;
}

static void print_headers()
{
	const char *fs = fs_configs[fs_type].fs;

	if (csv) {
		printf("ENDTIME_ns,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE\n");
		return;
	}

	if (min_lat_ms)
		printf("Tracing %s operations slower than %llu ms", fs, min_lat_ms);
	else
		printf("Tracing %s operations", fs);

	if (duration)
		printf(" for %ld secs.\n", duration);
	else
		printf("... Hit Ctrl-C to end.\n");

	printf("%-8s %-16s %-7s %1s %-10s %-8s %7s %s\n",
	       "TIME", "COMM", "PID", "T", "BYTES", "OFF_KB", "LAT(ms)", "FILENAME");
}
