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