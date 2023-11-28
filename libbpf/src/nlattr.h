#ifndef __LIBBPF_NLATTR_H
#define __LIBBPF_NLATTR_H

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#define __LINUX_NETLINK_H
enum
{
    LIBBPF_NLA_UNSPEC, /**< Unspecified type, binary data chunk */
    LIBBPF_NLA_U8,     /**< 8 bit integer */
    LIBBPF_NLA_U16,    /**< 16 bit integer */
    LIBBPF_NLA_U32,    /**< 32 bit integer */
    LIBBPF_NLA_U64,    /**< 64 bit integer */
    LIBBPF_NLA_STRING, /**< NUL terminated character string */
    LIBBPF_NLA_FLAG,   /**< Flag */
    LIBBPF_NLA_MSECS,  /**< Micro seconds (64bit) */
    LIBBPF_NLA_NESTED, /**< Nested attributes */
    __LIBBPF_NLA_TYPE_MAX,
};

#define LIBBPF_NLA_TYPE_MAX (__LIBBPF_NLA_TYPE_MAX - 1)
struct libbpf_nla_policy
{
    uint16_t type;
    uint16_t minlen;
    uint16_t maxlen;
};

struct libbpf_nla_req
{
    struct nlmsghdr nh;
    union
    {
        struct ifinfomsg ifinfo;
        struct tcmsg tc;
        struct genlmsghdr gnl;
    };
    char buf[128];
};

#define libbpf_nla_for_each_attr(pos, head, len, rem) \
    for (pos = head, rem = len;                       \
         nla_ok(pos, rem);                            \
         pos = nla_next(pos, &(rem)))
