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
