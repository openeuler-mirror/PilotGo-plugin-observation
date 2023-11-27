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

static int netlink_recvmsg(int sock, struct msghdr *mhdr, int flags)
{
    int len;

    do
    {
        len = recvmsg(sock, mhdr, flags);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len < 0)
        return -errno;
    return len;
}

static int alloc_iov(struct iovec *iov, int len)
{
    void *nbuf;

    nbuf = realloc(iov->iov_base, len);
    if (!nbuf)
        return -ENOMEM;

    iov->iov_base = nbuf;
    iov->iov_len = len;
    return 0;
}

static int libbpf_netlink_recv(int sock, __u32 nl_pid, int seq,
                               __dump_nlmsg_t _fn, libbpf_dump_nlmsg_t fn,
                               void *cookie)
{
    struct iovec iov = {};
    struct msghdr mhdr = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    bool multipart = true;
    struct nlmsgerr *err;
    struct nlmsghdr *nh;
    int len, ret;

    ret = alloc_iov(&iov, 4096);
    if (ret)
        goto done;

    while (multipart)
    {
    start:
        multipart = false;
        len = netlink_recvmsg(sock, &mhdr, MSG_PEEK | MSG_TRUNC);
        if (len < 0)
        {
            ret = len;
            goto done;
        }

        if (len > iov.iov_len)
        {
            ret = alloc_iov(&iov, len);
            if (ret)
                goto done;
        }

        len = netlink_recvmsg(sock, &mhdr, 0);
        if (len < 0)
        {
            ret = len;
            goto done;
        }

        if (len == 0)
            break;

        for (nh = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len))
        {
            if (nh->nlmsg_pid != nl_pid)
            {
                ret = -LIBBPF_ERRNO__WRNGPID;
                goto done;
            }
            if (nh->nlmsg_seq != seq)
            {
                ret = -LIBBPF_ERRNO__INVSEQ;
                goto done;
            }
            if (nh->nlmsg_flags & NLM_F_MULTI)
                multipart = true;
            switch (nh->nlmsg_type)
            {
            case NLMSG_ERROR:
                err = (struct nlmsgerr *)NLMSG_DATA(nh);
                if (!err->error)
                    continue;
                ret = err->error;
                libbpf_nla_dump_errormsg(nh);
                goto done;
            case NLMSG_DONE:
                ret = 0;
                goto done;
            default:
                break;
            }
            if (_fn)
            {
                ret = _fn(nh, fn, cookie);
                switch (ret)
                {
                case NL_CONT:
                    break;
                case NL_NEXT:
                    goto start;
                case NL_DONE:
                    ret = 0;
                    goto done;
                default:
                    goto done;
                }
            }
        }
    }
    ret = 0;
done:
    free(iov.iov_base);
    return ret;
}
static int libbpf_netlink_send_recv(struct libbpf_nla_req *req,
                                    int proto, __dump_nlmsg_t parse_msg,
                                    libbpf_dump_nlmsg_t parse_attr,
                                    void *cookie)
{
    __u32 nl_pid = 0;
    int sock, ret;

    sock = libbpf_netlink_open(&nl_pid, proto);
    if (sock < 0)
        return sock;

    req->nh.nlmsg_pid = 0;
    req->nh.nlmsg_seq = time(NULL);

    if (send(sock, req, req->nh.nlmsg_len, 0) < 0)
    {
        ret = -errno;
        goto out;
    }

    ret = libbpf_netlink_recv(sock, nl_pid, req->nh.nlmsg_seq,
                              parse_msg, parse_attr, cookie);
out:
    libbpf_netlink_close(sock);
    return ret;
}

static int parse_genl_family_id(struct nlmsghdr *nh, libbpf_dump_nlmsg_t fn,
                                void *cookie)
{
    struct genlmsghdr *gnl = NLMSG_DATA(nh);
    struct nlattr *na = (struct nlattr *)((void *)gnl + GENL_HDRLEN);
    struct nlattr *tb[CTRL_ATTR_FAMILY_ID + 1];
    __u16 *id = cookie;

    libbpf_nla_parse(tb, CTRL_ATTR_FAMILY_ID, na,
                     NLMSG_PAYLOAD(nh, sizeof(*gnl)), NULL);
    if (!tb[CTRL_ATTR_FAMILY_ID])
        return NL_CONT;

    *id = libbpf_nla_getattr_u16(tb[CTRL_ATTR_FAMILY_ID]);
    return NL_DONE;
}

static int libbpf_netlink_resolve_genl_family_id(const char *name,
                                                 __u16 len, __u16 *id)
{
    struct libbpf_nla_req req = {
        .nh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
        .nh.nlmsg_type = GENL_ID_CTRL,
        .nh.nlmsg_flags = NLM_F_REQUEST,
        .gnl.cmd = CTRL_CMD_GETFAMILY,
        .gnl.version = 2,
    };
    int err;

    err = nlattr_add(&req, CTRL_ATTR_FAMILY_NAME, name, len);
    if (err < 0)
        return err;

    return libbpf_netlink_send_recv(&req, NETLINK_GENERIC,
                                    parse_genl_family_id, NULL, id);
}

static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd,
                                         __u32 flags)
{
    struct nlattr *nla;
    int ret;
    struct libbpf_nla_req req;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_type = RTM_SETLINK;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = ifindex;

    nla = nlattr_begin_nested(&req, IFLA_XDP);
    if (!nla)
        return -EMSGSIZE;
    ret = nlattr_add(&req, IFLA_XDP_FD, &fd, sizeof(fd));
    if (ret < 0)
        return ret;
    if (flags)
    {
        ret = nlattr_add(&req, IFLA_XDP_FLAGS, &flags, sizeof(flags));
        if (ret < 0)
            return ret;
    }
    if (flags & XDP_FLAGS_REPLACE)
    {
        ret = nlattr_add(&req, IFLA_XDP_EXPECTED_FD, &old_fd,
                         sizeof(old_fd));
        if (ret < 0)
            return ret;
    }
    nlattr_end_nested(&req, nla);

    return libbpf_netlink_send_recv(&req, NETLINK_ROUTE, NULL, NULL, NULL);
}
int bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags, const struct bpf_xdp_attach_opts *opts)
{
    int old_prog_fd, err;

    if (!OPTS_VALID(opts, bpf_xdp_attach_opts))
        return libbpf_err(-EINVAL);

    old_prog_fd = OPTS_GET(opts, old_prog_fd, 0);
    if (old_prog_fd)
        flags |= XDP_FLAGS_REPLACE;
    else
        old_prog_fd = -1;

    err = __bpf_set_link_xdp_fd_replace(ifindex, prog_fd, old_prog_fd, flags);
    return libbpf_err(err);
}

int bpf_xdp_detach(int ifindex, __u32 flags, const struct bpf_xdp_attach_opts *opts)
{
    return bpf_xdp_attach(ifindex, -1, flags, opts);
}

static int __dump_link_nlmsg(struct nlmsghdr *nlh,
                             libbpf_dump_nlmsg_t dump_link_nlmsg, void *cookie)
{
    struct nlattr *tb[IFLA_MAX + 1], *attr;
    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    int len;

    len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
    attr = (struct nlattr *)((void *)ifi + NLMSG_ALIGN(sizeof(*ifi)));

    if (libbpf_nla_parse(tb, IFLA_MAX, attr, len, NULL) != 0)
        return -LIBBPF_ERRNO__NLPARSE;

    return dump_link_nlmsg(cookie, ifi, tb);
}