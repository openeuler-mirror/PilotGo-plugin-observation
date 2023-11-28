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

static inline void *libbpf_nla_data(const struct nlattr *nla)
{
    return (void *)nla + NLA_HDRLEN;
}

static inline uint8_t libbpf_nla_getattr_u8(const struct nlattr *nla)
{
    return *(uint8_t *)libbpf_nla_data(nla);
}

static inline uint16_t libbpf_nla_getattr_u16(const struct nlattr *nla)
{
    return *(uint16_t *)libbpf_nla_data(nla);
}

static inline uint32_t libbpf_nla_getattr_u32(const struct nlattr *nla)
{
    return *(uint32_t *)libbpf_nla_data(nla);
}

static inline uint64_t libbpf_nla_getattr_u64(const struct nlattr *nla)
{
    return *(uint64_t *)libbpf_nla_data(nla);
}

static inline const char *libbpf_nla_getattr_str(const struct nlattr *nla)
{
    return (const char *)libbpf_nla_data(nla);
}

static inline int libbpf_nla_len(const struct nlattr *nla)
{
    return nla->nla_len - NLA_HDRLEN;
}

int libbpf_nla_parse(struct nlattr *tb[], int maxtype, struct nlattr *head,
                     int len, struct libbpf_nla_policy *policy);
int libbpf_nla_parse_nested(struct nlattr *tb[], int maxtype,
                            struct nlattr *nla,
                            struct libbpf_nla_policy *policy);

int libbpf_nla_dump_errormsg(struct nlmsghdr *nlh);

static inline struct nlattr *nla_data(struct nlattr *nla)
{
    return (struct nlattr *)((void *)nla + NLA_HDRLEN);
}

static inline struct nlattr *req_tail(struct libbpf_nla_req *req)
{
    return (struct nlattr *)((void *)req + NLMSG_ALIGN(req->nh.nlmsg_len));
}