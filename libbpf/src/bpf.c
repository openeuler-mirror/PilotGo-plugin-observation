
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <limits.h>
#include <sys/resource.h>
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

int bpf_map_create(enum bpf_map_type map_type,
		   const char *map_name,
		   __u32 key_size,
		   __u32 value_size,
		   __u32 max_entries,
		   const struct bpf_map_create_opts *opts)
{
	const size_t attr_sz = offsetofend(union bpf_attr, map_extra);
	union bpf_attr attr;
	int fd;

	bump_rlimit_memlock();

	memset(&attr, 0, attr_sz);

	if (!OPTS_VALID(opts, bpf_map_create_opts))
		return libbpf_err(-EINVAL);

	attr.map_type = map_type;
	if (map_name && kernel_supports(NULL, FEAT_PROG_NAME))
		libbpf_strlcpy(attr.map_name, map_name, sizeof(attr.map_name));
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	attr.btf_fd = OPTS_GET(opts, btf_fd, 0);
	attr.btf_key_type_id = OPTS_GET(opts, btf_key_type_id, 0);
	attr.btf_value_type_id = OPTS_GET(opts, btf_value_type_id, 0);
	attr.btf_vmlinux_value_type_id = OPTS_GET(opts, btf_vmlinux_value_type_id, 0);

	attr.inner_map_fd = OPTS_GET(opts, inner_map_fd, 0);
	attr.map_flags = OPTS_GET(opts, map_flags, 0);
	attr.map_extra = OPTS_GET(opts, map_extra, 0);
	attr.numa_node = OPTS_GET(opts, numa_node, 0);
	attr.map_ifindex = OPTS_GET(opts, map_ifindex, 0);

	fd = sys_bpf_fd(BPF_MAP_CREATE, &attr, attr_sz);
	return libbpf_err_errno(fd);
}

int bpf_prog_load(enum bpf_prog_type prog_type,
		  const char *prog_name, const char *license,
		  const struct bpf_insn *insns, size_t insn_cnt,
		  struct bpf_prog_load_opts *opts)
{
	const size_t attr_sz = offsetofend(union bpf_attr, log_true_size);
	void *finfo = NULL, *linfo = NULL;
	const char *func_info, *line_info;
	__u32 log_size, log_level, attach_prog_fd, attach_btf_obj_fd;
	__u32 func_info_rec_size, line_info_rec_size;
	int fd, attempts;
	union bpf_attr attr;
	char *log_buf;

	bump_rlimit_memlock();

	if (!OPTS_VALID(opts, bpf_prog_load_opts))
		return libbpf_err(-EINVAL);

	attempts = OPTS_GET(opts, attempts, 0);
	if (attempts < 0)
		return libbpf_err(-EINVAL);
	if (attempts == 0)
		attempts = PROG_LOAD_ATTEMPTS;

	memset(&attr, 0, attr_sz);

	attr.prog_type = prog_type;
	attr.expected_attach_type = OPTS_GET(opts, expected_attach_type, 0);

	attr.prog_btf_fd = OPTS_GET(opts, prog_btf_fd, 0);
	attr.prog_flags = OPTS_GET(opts, prog_flags, 0);
	attr.prog_ifindex = OPTS_GET(opts, prog_ifindex, 0);
	attr.kern_version = OPTS_GET(opts, kern_version, 0);

	if (prog_name && kernel_supports(NULL, FEAT_PROG_NAME))
		libbpf_strlcpy(attr.prog_name, prog_name, sizeof(attr.prog_name));
	attr.license = ptr_to_u64(license);

	if (insn_cnt > UINT_MAX)
		return libbpf_err(-E2BIG);

	attr.insns = ptr_to_u64(insns);
	attr.insn_cnt = (__u32)insn_cnt;

	attach_prog_fd = OPTS_GET(opts, attach_prog_fd, 0);
	attach_btf_obj_fd = OPTS_GET(opts, attach_btf_obj_fd, 0);

	if (attach_prog_fd && attach_btf_obj_fd)
		return libbpf_err(-EINVAL);

	attr.attach_btf_id = OPTS_GET(opts, attach_btf_id, 0);
	if (attach_prog_fd)
		attr.attach_prog_fd = attach_prog_fd;
	else
		attr.attach_btf_obj_fd = attach_btf_obj_fd;

	log_buf = OPTS_GET(opts, log_buf, NULL);
	log_size = OPTS_GET(opts, log_size, 0);
	log_level = OPTS_GET(opts, log_level, 0);

	if (!!log_buf != !!log_size)
		return libbpf_err(-EINVAL);

	func_info_rec_size = OPTS_GET(opts, func_info_rec_size, 0);
	func_info = OPTS_GET(opts, func_info, NULL);
	attr.func_info_rec_size = func_info_rec_size;
	attr.func_info = ptr_to_u64(func_info);
	attr.func_info_cnt = OPTS_GET(opts, func_info_cnt, 0);

	line_info_rec_size = OPTS_GET(opts, line_info_rec_size, 0);
	line_info = OPTS_GET(opts, line_info, NULL);
	attr.line_info_rec_size = line_info_rec_size;
	attr.line_info = ptr_to_u64(line_info);
	attr.line_info_cnt = OPTS_GET(opts, line_info_cnt, 0);

	attr.fd_array = ptr_to_u64(OPTS_GET(opts, fd_array, NULL));

	if (log_level) {
		attr.log_buf = ptr_to_u64(log_buf);
		attr.log_size = log_size;
		attr.log_level = log_level;
	}

	fd = sys_bpf_prog_load(&attr, attr_sz, attempts);
	OPTS_SET(opts, log_true_size, attr.log_true_size);
	if (fd >= 0)
		return fd;

	/* After bpf_prog_load, the kernel may modify certain attributes
	 * to give user space a hint how to deal with loading failure.
	 * Check to see whether we can make some changes and load again.
	 */
	while (errno == E2BIG && (!finfo || !linfo)) {
		if (!finfo && attr.func_info_cnt &&
		    attr.func_info_rec_size < func_info_rec_size) {
			/* try with corrected func info records */
			finfo = alloc_zero_tailing_info(func_info,
							attr.func_info_cnt,
							func_info_rec_size,
							attr.func_info_rec_size);
			if (!finfo) {
				errno = E2BIG;
				goto done;
			}

			attr.func_info = ptr_to_u64(finfo);
			attr.func_info_rec_size = func_info_rec_size;
		} else if (!linfo && attr.line_info_cnt &&
			   attr.line_info_rec_size < line_info_rec_size) {
			linfo = alloc_zero_tailing_info(line_info,
							attr.line_info_cnt,
							line_info_rec_size,
							attr.line_info_rec_size);
			if (!linfo) {
				errno = E2BIG;
				goto done;
			}

			attr.line_info = ptr_to_u64(linfo);
			attr.line_info_rec_size = line_info_rec_size;
		} else {
			break;
		}

		fd = sys_bpf_prog_load(&attr, attr_sz, attempts);
		OPTS_SET(opts, log_true_size, attr.log_true_size);
		if (fd >= 0)
			goto done;
	}

	if (log_level == 0 && log_buf) {
		/* log_level == 0 with non-NULL log_buf requires retrying on error
		 * with log_level == 1 and log_buf/log_buf_size set, to get details of
		 * failure
		 */
		attr.log_buf = ptr_to_u64(log_buf);
		attr.log_size = log_size;
		attr.log_level = 1;

		fd = sys_bpf_prog_load(&attr, attr_sz, attempts);
		OPTS_SET(opts, log_true_size, attr.log_true_size);
	}
done:
	/* free() doesn't affect errno, so we don't need to restore it */
	free(finfo);
	free(linfo);
	return libbpf_err_errno(fd);
}

int bpf_map_update_elem(int fd, const void *key, const void *value,
			__u64 flags)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	ret = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	ret = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_lookup_elem_flags(int fd, const void *key, void *value, __u64 flags)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	ret = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	ret = sys_bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_lookup_and_delete_elem_flags(int fd, const void *key, void *value, __u64 flags)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	ret = sys_bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_delete_elem(int fd, const void *key)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	ret = sys_bpf(BPF_MAP_DELETE_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_delete_elem_flags(int fd, const void *key, __u64 flags)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.flags = flags;

	ret = sys_bpf(BPF_MAP_DELETE_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	const size_t attr_sz = offsetofend(union bpf_attr, next_key);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	ret = sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_freeze(int fd)
{
	const size_t attr_sz = offsetofend(union bpf_attr, map_fd);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;

	ret = sys_bpf(BPF_MAP_FREEZE, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

static int bpf_map_batch_common(int cmd, int fd, void  *in_batch,
				void *out_batch, void *keys, void *values,
				__u32 *count,
				const struct bpf_map_batch_opts *opts)
{
	const size_t attr_sz = offsetofend(union bpf_attr, batch);
	union bpf_attr attr;
	int ret;

	if (!OPTS_VALID(opts, bpf_map_batch_opts))
		return libbpf_err(-EINVAL);

	memset(&attr, 0, attr_sz);
	attr.batch.map_fd = fd;
	attr.batch.in_batch = ptr_to_u64(in_batch);
	attr.batch.out_batch = ptr_to_u64(out_batch);
	attr.batch.keys = ptr_to_u64(keys);
	attr.batch.values = ptr_to_u64(values);
	attr.batch.count = *count;
	attr.batch.elem_flags  = OPTS_GET(opts, elem_flags, 0);
	attr.batch.flags = OPTS_GET(opts, flags, 0);

	ret = sys_bpf(cmd, &attr, attr_sz);
	*count = attr.batch.count;

	return libbpf_err_errno(ret);
}

int bpf_map_delete_batch(int fd, const void *keys, __u32 *count,
			 const struct bpf_map_batch_opts *opts)
{
	return bpf_map_batch_common(BPF_MAP_DELETE_BATCH, fd, NULL,
				    NULL, (void *)keys, NULL, count, opts);
}

int bpf_map_lookup_batch(int fd, void *in_batch, void *out_batch, void *keys,
			 void *values, __u32 *count,
			 const struct bpf_map_batch_opts *opts)
{
	return bpf_map_batch_common(BPF_MAP_LOOKUP_BATCH, fd, in_batch,
				    out_batch, keys, values, count, opts);
}

int bpf_map_lookup_and_delete_batch(int fd, void *in_batch, void *out_batch,
				    void *keys, void *values, __u32 *count,
				    const struct bpf_map_batch_opts *opts)
{
	return bpf_map_batch_common(BPF_MAP_LOOKUP_AND_DELETE_BATCH,
				    fd, in_batch, out_batch, keys, values,
				    count, opts);
}

int bpf_map_update_batch(int fd, const void *keys, const void *values, __u32 *count,
			 const struct bpf_map_batch_opts *opts)
{
	return bpf_map_batch_common(BPF_MAP_UPDATE_BATCH, fd, NULL, NULL,
				    (void *)keys, (void *)values, count, opts);
}
