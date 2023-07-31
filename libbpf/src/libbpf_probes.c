#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/utsname.h>

#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

static __u32 get_ubuntu_kernel_version(void)
{
    const char *ubuntu_kver_file = "/proc/version_signature";
    __u32 major, minor, patch;
    int ret;
    FILE *f;

    if (faccessat(AT_FDCWD, ubuntu_kver_file, R_OK, AT_EACCESS) != 0)
        return 0;

    f = fopen(ubuntu_kver_file, "r");
    if (!f)
        return 0;

    ret = fscanf(f, "%*s %*s %u.%u.%u\n", &major, &minor, &patch);
    fclose(f);
    if (ret != 3)
        return 0;

    return KERNEL_VERSION(major, minor, patch);
}

static __u32 get_debian_kernel_version(struct utsname *info)
{
    __u32 major, minor, patch;
    char *p;

    p = strstr(info->version, "Debian ");
    if (!p)
    {
        /* This is not a Debian kernel. */
        return 0;
    }

    if (sscanf(p, "Debian %u.%u.%u", &major, &minor, &patch) != 3)
        return 0;

    return KERNEL_VERSION(major, minor, patch);
}

static int probe_prog_load(enum bpf_prog_type prog_type,
                           const struct bpf_insn *insns, size_t insns_cnt,
                           char *log_buf, size_t log_buf_sz)
{
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
                .log_buf = log_buf,
                .log_size = log_buf_sz,
                .log_level = log_buf ? 1 : 0, );
    int fd, err, exp_err = 0;
    const char *exp_msg = NULL;
    char buf[4096];

    switch (prog_type)
    {
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
        opts.expected_attach_type = BPF_CGROUP_INET4_CONNECT;
        break;
    case BPF_PROG_TYPE_CGROUP_SOCKOPT:
        opts.expected_attach_type = BPF_CGROUP_GETSOCKOPT;
        break;
    case BPF_PROG_TYPE_SK_LOOKUP:
        opts.expected_attach_type = BPF_SK_LOOKUP;
        break;
    case BPF_PROG_TYPE_KPROBE:
        opts.kern_version = get_kernel_version();
        break;
    case BPF_PROG_TYPE_LIRC_MODE2:
        opts.expected_attach_type = BPF_LIRC_MODE2;
        break;
    case BPF_PROG_TYPE_TRACING:
    case BPF_PROG_TYPE_LSM:
        opts.log_buf = buf;
        opts.log_size = sizeof(buf);
        opts.log_level = 1;
        if (prog_type == BPF_PROG_TYPE_TRACING)
            opts.expected_attach_type = BPF_TRACE_FENTRY;
        else
            opts.expected_attach_type = BPF_MODIFY_RETURN;
        opts.attach_btf_id = 1;

        exp_err = -EINVAL;
        exp_msg = "attach_btf_id 1 is not a function";
        break;
    case BPF_PROG_TYPE_EXT:
        opts.log_buf = buf;
        opts.log_size = sizeof(buf);
        opts.log_level = 1;
        opts.attach_btf_id = 1;

        exp_err = -EINVAL;
        exp_msg = "Cannot replace kernel functions";
        break;
    case BPF_PROG_TYPE_SYSCALL:
        opts.prog_flags = BPF_F_SLEEPABLE;
        break;
    case BPF_PROG_TYPE_STRUCT_OPS:
        exp_err = -524; /* -ENOTSUPP */
        break;
    case BPF_PROG_TYPE_UNSPEC:
    case BPF_PROG_TYPE_SOCKET_FILTER:
    case BPF_PROG_TYPE_SCHED_CLS:
    case BPF_PROG_TYPE_SCHED_ACT:
    case BPF_PROG_TYPE_TRACEPOINT:
    case BPF_PROG_TYPE_XDP:
    case BPF_PROG_TYPE_PERF_EVENT:
    case BPF_PROG_TYPE_CGROUP_SKB:
    case BPF_PROG_TYPE_CGROUP_SOCK:
    case BPF_PROG_TYPE_LWT_IN:
    case BPF_PROG_TYPE_LWT_OUT:
    case BPF_PROG_TYPE_LWT_XMIT:
    case BPF_PROG_TYPE_SOCK_OPS:
    case BPF_PROG_TYPE_SK_SKB:
    case BPF_PROG_TYPE_CGROUP_DEVICE:
    case BPF_PROG_TYPE_SK_MSG:
    case BPF_PROG_TYPE_RAW_TRACEPOINT:
    case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
    case BPF_PROG_TYPE_LWT_SEG6LOCAL:
    case BPF_PROG_TYPE_SK_REUSEPORT:
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
    case BPF_PROG_TYPE_CGROUP_SYSCTL:
        break;
    default:
        return -EOPNOTSUPP;
    }

    fd = bpf_prog_load(prog_type, NULL, "GPL", insns, insns_cnt, &opts);
    err = -errno;
    if (fd >= 0)
        close(fd);
    if (exp_err)
    {
        if (fd >= 0 || err != exp_err)
            return 0;
        if (exp_msg && !strstr(buf, exp_msg))
            return 0;
        return 1;
    }
    return fd >= 0 ? 1 : 0;
}

__u32 get_kernel_version(void)
{
    __u32 major, minor, patch, version;
    struct utsname info;

    /* Check if this is an Ubuntu kernel. */
    version = get_ubuntu_kernel_version();
    if (version != 0)
        return version;

    uname(&info);

    /* Check if this is a Debian kernel. */
    version = get_debian_kernel_version(&info);
    if (version != 0)
        return version;

    if (sscanf(info.release, "%u.%u.%u", &major, &minor, &patch) != 3)
        return 0;

    return KERNEL_VERSION(major, minor, patch);
}

int libbpf_probe_bpf_prog_type(enum bpf_prog_type prog_type, const void *opts)
{
    struct bpf_insn insns[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN()};
    const size_t insn_cnt = ARRAY_SIZE(insns);
    int ret;

    if (opts)
        return libbpf_err(-EINVAL);

    ret = probe_prog_load(prog_type, insns, insn_cnt, NULL, 0);
    return libbpf_err(ret);
}

int libbpf_probe_bpf_map_type(enum bpf_map_type map_type, const void *opts)
{
    int ret;

    if (opts)
        return libbpf_err(-EINVAL);

    ret = probe_map_create(map_type);
    return libbpf_err(ret);
}