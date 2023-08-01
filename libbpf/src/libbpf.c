#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <libgen.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <asm/unistd.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/ring_buffer.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <libelf.h>
#include <gelf.h>
#include <zlib.h>

#include "libbpf.h"
#include "bpf.h"
#include "btf.h"
#include "str_error.h"
#include "libbpf_internal.h"
#include "hashmap.h"
#include "bpf_gen_internal.h"
#include "zip.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#define BPF_INSN_SZ (sizeof(struct bpf_insn))
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

#define __printf(a, b) __attribute__((format(printf, a, b)))

static struct bpf_map *bpf_object__add_map(struct bpf_object *obj);
static bool prog_is_subprog(const struct bpf_object *obj, const struct bpf_program *prog);

static const char *const attach_type_name[] = {
    [BPF_CGROUP_INET_INGRESS] = "cgroup_inet_ingress",
    [BPF_CGROUP_INET_EGRESS] = "cgroup_inet_egress",
    [BPF_CGROUP_INET_SOCK_CREATE] = "cgroup_inet_sock_create",
    [BPF_CGROUP_INET_SOCK_RELEASE] = "cgroup_inet_sock_release",
    [BPF_CGROUP_SOCK_OPS] = "cgroup_sock_ops",
    [BPF_CGROUP_DEVICE] = "cgroup_device",
    [BPF_CGROUP_INET4_BIND] = "cgroup_inet4_bind",
    [BPF_CGROUP_INET6_BIND] = "cgroup_inet6_bind",
    [BPF_CGROUP_INET4_CONNECT] = "cgroup_inet4_connect",
    [BPF_CGROUP_INET6_CONNECT] = "cgroup_inet6_connect",
    [BPF_CGROUP_INET4_POST_BIND] = "cgroup_inet4_post_bind",
    [BPF_CGROUP_INET6_POST_BIND] = "cgroup_inet6_post_bind",
    [BPF_CGROUP_INET4_GETPEERNAME] = "cgroup_inet4_getpeername",
    [BPF_CGROUP_INET6_GETPEERNAME] = "cgroup_inet6_getpeername",
    [BPF_CGROUP_INET4_GETSOCKNAME] = "cgroup_inet4_getsockname",
    [BPF_CGROUP_INET6_GETSOCKNAME] = "cgroup_inet6_getsockname",
    [BPF_CGROUP_UDP4_SENDMSG] = "cgroup_udp4_sendmsg",
    [BPF_CGROUP_UDP6_SENDMSG] = "cgroup_udp6_sendmsg",
    [BPF_CGROUP_SYSCTL] = "cgroup_sysctl",
    [BPF_CGROUP_UDP4_RECVMSG] = "cgroup_udp4_recvmsg",
    [BPF_CGROUP_UDP6_RECVMSG] = "cgroup_udp6_recvmsg",
    [BPF_CGROUP_GETSOCKOPT] = "cgroup_getsockopt",
    [BPF_CGROUP_SETSOCKOPT] = "cgroup_setsockopt",
    [BPF_SK_SKB_STREAM_PARSER] = "sk_skb_stream_parser",
    [BPF_SK_SKB_STREAM_VERDICT] = "sk_skb_stream_verdict",
    [BPF_SK_SKB_VERDICT] = "sk_skb_verdict",
    [BPF_SK_MSG_VERDICT] = "sk_msg_verdict",
    [BPF_LIRC_MODE2] = "lirc_mode2",
    [BPF_FLOW_DISSECTOR] = "flow_dissector",
    [BPF_TRACE_RAW_TP] = "trace_raw_tp",
    [BPF_TRACE_FENTRY] = "trace_fentry",
    [BPF_TRACE_FEXIT] = "trace_fexit",
    [BPF_MODIFY_RETURN] = "modify_return",
    [BPF_LSM_MAC] = "lsm_mac",
    [BPF_LSM_CGROUP] = "lsm_cgroup",
    [BPF_SK_LOOKUP] = "sk_lookup",
    [BPF_TRACE_ITER] = "trace_iter",
    [BPF_XDP_DEVMAP] = "xdp_devmap",
    [BPF_XDP_CPUMAP] = "xdp_cpumap",
    [BPF_XDP] = "xdp",
    [BPF_SK_REUSEPORT_SELECT] = "sk_reuseport_select",
    [BPF_SK_REUSEPORT_SELECT_OR_MIGRATE] = "sk_reuseport_select_or_migrate",
    [BPF_PERF_EVENT] = "perf_event",
    [BPF_TRACE_KPROBE_MULTI] = "trace_kprobe_multi",
    [BPF_STRUCT_OPS] = "struct_ops",
};