#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>
#include <linux/netdev.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "nlattr.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

typedef int (*libbpf_dump_nlmsg_t)(void *cookie, void *msg, struct nlattr **tb);

typedef int (*__dump_nlmsg_t)(struct nlmsghdr *nlmsg, libbpf_dump_nlmsg_t,
                              void *cookie);

struct xdp_link_info
{
    __u32 prog_id;
    __u32 drv_prog_id;
    __u32 hw_prog_id;
    __u32 skb_prog_id;
    __u8 attach_mode;
};

struct xdp_id_md
{
    int ifindex;
    __u32 flags;
    struct xdp_link_info info;
    __u64 feature_flags;
};

struct xdp_features_md
{
    int ifindex;
    __u64 flags;
};
static int libbpf_netlink_open(__u32 *nl_pid, int proto)
{
    struct sockaddr_nl sa;
    socklen_t addrlen;
    int one = 1, ret;
    int sock;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto);
    if (sock < 0)
        return -errno;

    if (setsockopt(sock, SOL_NETLINK, NETLINK_EXT_ACK,
                   &one, sizeof(one)) < 0)
    {
        pr_warn("Netlink error reporting not supported\n");
    }

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        ret = -errno;
        goto cleanup;
    }

    addrlen = sizeof(sa);
    if (getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0)
    {
        ret = -errno;
        goto cleanup;
    }

    if (addrlen != sizeof(sa))
    {
        ret = -LIBBPF_ERRNO__INTERNAL;
        goto cleanup;
    }

    *nl_pid = sa.nl_pid;
    return sock;

cleanup:
    close(sock);
    return ret;
}

static void libbpf_netlink_close(int sock)
{
    close(sock);
}

enum
{
    NL_CONT,
    NL_NEXT,
    NL_DONE,
};