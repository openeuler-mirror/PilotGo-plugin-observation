#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <linux/rtnetlink.h>
#include "nlattr.h"
#include "libbpf_internal.h"

static uint16_t nla_attr_minlen[LIBBPF_NLA_TYPE_MAX + 1] = {
    [LIBBPF_NLA_U8] = sizeof(uint8_t),
    [LIBBPF_NLA_U16] = sizeof(uint16_t),
    [LIBBPF_NLA_U32] = sizeof(uint32_t),
    [LIBBPF_NLA_U64] = sizeof(uint64_t),
    [LIBBPF_NLA_STRING] = 1,
    [LIBBPF_NLA_FLAG] = 0,
};

static struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
    int totlen = NLA_ALIGN(nla->nla_len);

    *remaining -= totlen;
    return (struct nlattr *)((void *)nla + totlen);
}

static int nla_ok(const struct nlattr *nla, int remaining)
{
    return remaining >= (int)sizeof(*nla) &&
           nla->nla_len >= sizeof(*nla) &&
           nla->nla_len <= remaining;
}

static int nla_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

static int validate_nla(struct nlattr *nla, int maxtype,
                        struct libbpf_nla_policy *policy)
{
    struct libbpf_nla_policy *pt;
    unsigned int minlen = 0;
    int type = nla_type(nla);

    if (type < 0 || type > maxtype)
        return 0;

    pt = &policy[type];

    if (pt->type > LIBBPF_NLA_TYPE_MAX)
        return 0;

    if (pt->minlen)
        minlen = pt->minlen;
    else if (pt->type != LIBBPF_NLA_UNSPEC)
        minlen = nla_attr_minlen[pt->type];

    if (libbpf_nla_len(nla) < minlen)
        return -1;

    if (pt->maxlen && libbpf_nla_len(nla) > pt->maxlen)
        return -1;

    if (pt->type == LIBBPF_NLA_STRING)
    {
        char *data = libbpf_nla_data(nla);

        if (data[libbpf_nla_len(nla) - 1] != '\0')
            return -1;
    }

    return 0;
}
