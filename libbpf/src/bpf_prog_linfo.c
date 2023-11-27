// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <string.h>
#include <stdlib.h>
#include <linux/err.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "libbpf_internal.h"

struct bpf_prog_linfo {
	void *raw_linfo;
	void *raw_jited_linfo;
	__u32 *nr_jited_linfo_per_func;
	__u32 *jited_linfo_func_idx;
	__u32 nr_linfo;
	__u32 nr_jited_func;
	__u32 rec_size;
	__u32 jited_rec_size;
};

static int dissect_jited_func(struct bpf_prog_linfo *prog_linfo,
			      const __u64 *ksym_func, const __u32 *ksym_len)
{
	__u32 nr_jited_func, nr_linfo;
	const void *raw_jited_linfo;
	const __u64 *jited_linfo;
	__u64 last_jited_linfo;
	/*
	 * Index to raw_jited_linfo:
	 *      i: Index for searching the next ksym_func
	 * prev_i: Index to the last found ksym_func
	 */
	__u32 i, prev_i;
	__u32 f; /* Index to ksym_func */

	raw_jited_linfo = prog_linfo->raw_jited_linfo;
	jited_linfo = raw_jited_linfo;
	if (ksym_func[0] != *jited_linfo)
		goto errout;

	prog_linfo->jited_linfo_func_idx[0] = 0;
	nr_jited_func = prog_linfo->nr_jited_func;
	nr_linfo = prog_linfo->nr_linfo;

	for (prev_i = 0, i = 1, f = 1;
	     i < nr_linfo && f < nr_jited_func;
	     i++) {
		raw_jited_linfo += prog_linfo->jited_rec_size;
		last_jited_linfo = *jited_linfo;
		jited_linfo = raw_jited_linfo;

		if (ksym_func[f] == *jited_linfo) {
			prog_linfo->jited_linfo_func_idx[f] = i;

			/* Sanity check */
			if (last_jited_linfo - ksym_func[f - 1] + 1 >
			    ksym_len[f - 1])
				goto errout;

			prog_linfo->nr_jited_linfo_per_func[f - 1] =
				i - prev_i;
			prev_i = i;

			/*
			 * The ksym_func[f] is found in jited_linfo.
			 * Look for the next one.
			 */
			f++;
		} else if (*jited_linfo <= last_jited_linfo) {
			/* Ensure the addr is increasing _within_ a func */
			goto errout;
		}
	}

	if (f != nr_jited_func)
		goto errout;

	prog_linfo->nr_jited_linfo_per_func[nr_jited_func - 1] =
		nr_linfo - prev_i;

	return 0;

errout:
	return -EINVAL;
}

void bpf_prog_linfo__free(struct bpf_prog_linfo *prog_linfo)
{
	if (!prog_linfo)
		return;

	free(prog_linfo->raw_linfo);
	free(prog_linfo->raw_jited_linfo);
	free(prog_linfo->nr_jited_linfo_per_func);
	free(prog_linfo->jited_linfo_func_idx);
	free(prog_linfo);
}

const struct bpf_line_info *
bpf_prog_linfo__lfind(const struct bpf_prog_linfo *prog_linfo,
		      __u32 insn_off, __u32 nr_skip)
{
	const struct bpf_line_info *linfo;
	__u32 rec_size, nr_linfo, i;
	const void *raw_linfo;

	nr_linfo = prog_linfo->nr_linfo;
	if (nr_skip >= nr_linfo)
		return errno = ENOENT, NULL;

	rec_size = prog_linfo->rec_size;
	raw_linfo = prog_linfo->raw_linfo + (nr_skip * rec_size);
	linfo = raw_linfo;
	if (insn_off < linfo->insn_off)
		return errno = ENOENT, NULL;

	nr_linfo -= nr_skip;
	for (i = 0; i < nr_linfo; i++) {
		if (insn_off < linfo->insn_off)
			break;

		raw_linfo += rec_size;
		linfo = raw_linfo;
	}

	return raw_linfo - rec_size;
}
