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
