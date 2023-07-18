#ifndef __LIBBPF_BPF_H
#define __LIBBPF_BPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbpf_common.h"
#include "libbpf_legacy.h"

#ifdef __cplusplus
extern "C" {
#endif

int libbpf_set_memlock_rlim(size_t memlock_bytes);

struct bpf_map_create_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	__u32 btf_fd;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 btf_vmlinux_value_type_id;

	__u32 inner_map_fd;
	__u32 map_flags;
	__u64 map_extra;

	__u32 numa_node;
	__u32 map_ifindex;
};
#define bpf_map_create_opts__last_field map_ifindex

LIBBPF_API int bpf_map_create(enum bpf_map_type map_type,
			      const char *map_name,
			      __u32 key_size,
			      __u32 value_size,
			      __u32 max_entries,
			      const struct bpf_map_create_opts *opts);

struct bpf_prog_load_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	int attempts;

	enum bpf_attach_type expected_attach_type;
	__u32 prog_btf_fd;
	__u32 prog_flags;
	__u32 prog_ifindex;
	__u32 kern_version;

	__u32 attach_btf_id;
	__u32 attach_prog_fd;
	__u32 attach_btf_obj_fd;

	const int *fd_array;

	/* .BTF.ext func info data */
	const void *func_info;
	__u32 func_info_cnt;
	__u32 func_info_rec_size;

	/* .BTF.ext line info data */
	const void *line_info;
	__u32 line_info_cnt;
	__u32 line_info_rec_size;

	/* verifier log options */
	__u32 log_level;
	__u32 log_size;
	char *log_buf;
	__u32 log_true_size;
	size_t :0;
};
#define bpf_prog_load_opts__last_field log_true_size

LIBBPF_API int bpf_prog_load(enum bpf_prog_type prog_type,
			     const char *prog_name, const char *license,
			     const struct bpf_insn *insns, size_t insn_cnt,
			     struct bpf_prog_load_opts *opts);

#define MAPS_RELAX_COMPAT	0x01

/* Recommended log buffer size */
#define BPF_LOG_BUF_SIZE (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */

struct bpf_btf_load_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	/* kernel log options */
	char *log_buf;
	__u32 log_level;
	__u32 log_size;

	__u32 log_true_size;
	size_t :0;
};
#define bpf_btf_load_opts__last_field log_true_size

LIBBPF_API int bpf_btf_load(const void *btf_data, size_t btf_size,
			    struct bpf_btf_load_opts *opts);

LIBBPF_API int bpf_map_update_elem(int fd, const void *key, const void *value,
				   __u64 flags);

LIBBPF_API int bpf_map_lookup_elem(int fd, const void *key, void *value);
LIBBPF_API int bpf_map_lookup_elem_flags(int fd, const void *key, void *value,
					 __u64 flags);
LIBBPF_API int bpf_map_lookup_and_delete_elem(int fd, const void *key,
					      void *value);
LIBBPF_API int bpf_map_lookup_and_delete_elem_flags(int fd, const void *key,
						    void *value, __u64 flags);
LIBBPF_API int bpf_map_delete_elem(int fd, const void *key);
LIBBPF_API int bpf_map_delete_elem_flags(int fd, const void *key, __u64 flags);
LIBBPF_API int bpf_map_get_next_key(int fd, const void *key, void *next_key);
LIBBPF_API int bpf_map_freeze(int fd);

struct bpf_map_batch_opts {
	size_t sz;
	__u64 elem_flags;
	__u64 flags;
};
#define bpf_map_batch_opts__last_field flags

LIBBPF_API int bpf_map_delete_batch(int fd, const void *keys,
				    __u32 *count,
				    const struct bpf_map_batch_opts *opts);

LIBBPF_API int bpf_map_lookup_batch(int fd, void *in_batch, void *out_batch,
				    void *keys, void *values, __u32 *count,
				    const struct bpf_map_batch_opts *opts);

LIBBPF_API int bpf_map_lookup_and_delete_batch(int fd, void *in_batch,
					void *out_batch, void *keys,
					void *values, __u32 *count,
					const struct bpf_map_batch_opts *opts);

LIBBPF_API int bpf_map_update_batch(int fd, const void *keys, const void *values,
				    __u32 *count,
				    const struct bpf_map_batch_opts *opts);

struct bpf_obj_get_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	__u32 file_flags;

	size_t :0;
};
#define bpf_obj_get_opts__last_field file_flags

LIBBPF_API int bpf_obj_pin(int fd, const char *pathname);
LIBBPF_API int bpf_obj_get(const char *pathname);
LIBBPF_API int bpf_obj_get_opts(const char *pathname,
				const struct bpf_obj_get_opts *opts);

struct bpf_prog_attach_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	unsigned int flags;
	int replace_prog_fd;
};
#define bpf_prog_attach_opts__last_field replace_prog_fd

LIBBPF_API int bpf_prog_attach(int prog_fd, int attachable_fd,
			       enum bpf_attach_type type, unsigned int flags);
LIBBPF_API int bpf_prog_attach_opts(int prog_fd, int attachable_fd,
				     enum bpf_attach_type type,
				     const struct bpf_prog_attach_opts *opts);
LIBBPF_API int bpf_prog_detach(int attachable_fd, enum bpf_attach_type type);
LIBBPF_API int bpf_prog_detach2(int prog_fd, int attachable_fd,
				enum bpf_attach_type type);

union bpf_iter_link_info; /* defined in up-to-date linux/bpf.h */
struct bpf_link_create_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
	union bpf_iter_link_info *iter_info;
	__u32 iter_info_len;
	__u32 target_btf_id;
	union {
		struct {
			__u64 bpf_cookie;
		} perf_event;
		struct {
			__u32 flags;
			__u32 cnt;
			const char **syms;
			const unsigned long *addrs;
			const __u64 *cookies;
		} kprobe_multi;
		struct {
			__u64 cookie;
		} tracing;
	};
	size_t :0;
};
#define bpf_link_create_opts__last_field kprobe_multi.cookies

LIBBPF_API int bpf_link_create(int prog_fd, int target_fd,
			       enum bpf_attach_type attach_type,
			       const struct bpf_link_create_opts *opts);

LIBBPF_API int bpf_link_detach(int link_fd);

struct bpf_link_update_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;	   /* extra flags */
	__u32 old_prog_fd; /* expected old program FD */
	__u32 old_map_fd;  /* expected old map FD */
};
#define bpf_link_update_opts__last_field old_map_fd

LIBBPF_API int bpf_link_update(int link_fd, int new_prog_fd,
			       const struct bpf_link_update_opts *opts);

LIBBPF_API int bpf_iter_create(int link_fd);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBBPF_BPF_H */
