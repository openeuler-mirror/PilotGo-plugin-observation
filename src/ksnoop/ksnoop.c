// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "ksnoop.h"
#include "ksnoop.skel.h"
#include <bpf/btf.h>

#ifndef KSNOOP_VERSION
#define KSNOOP_VERSION	"0.1"
#endif

static volatile sig_atomic_t exiting;
static struct btf *vmlinux_btf;
static const char *bin_name;
static int pages = PAGES_DEFAULT;

enum log_level {
	DEBUG,
	WARN,
	ERROR,
};

static enum log_level log_level = WARN;
static bool verbose = false;

static __u32 filter_pid;
static bool stack_mode;

static void __p(enum log_level level, char *level_str, char *fmt, ...)
{
	va_list ap;

	if (level < log_level)
		return;
	va_start(ap, fmt);
	warning("%s: ", level_str);
	vfprintf(stderr, fmt, ap);
	warning("\n");
	va_end(ap);
	fflush(stderr);
}

#define pr_err(fmt, ...)	__p(ERROR, "Error", fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	__p(WARNING, "Warn", fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	__p(DEBUG, "Debug", fmt, ##__VA_ARGS__)

static int do_version(int argc, char *argv[])
{
	printf("%s v%s\n", bin_name, KSNOOP_VERSION);
	return 0;
}

static int cmd_help(int argc, char *argv[])
{
	warning("Usage: %s [OPTIONS] [COMMAND | help] FUNC\n"
		"	COMMAND	:= { trace | info }\n"
		"	FUNC	:= { name | name(ARG[,ARG]*) }\n"
		"	ARG	:= { arg | arg [PRED] | arg->member [PRED] }\n"
		"	PRED	:= { == | != | > | >= | < | <=  value }\n"
		"	OPTIONS	:= { {-d|--debug} | {-v|--verbose} | {-V|--version} |\n"
		"                    {-p|--pid filter_pid}|\n"
		"                    {-P|--pages nr_pages} }\n"
		"                    {-s|--stack}\n",
		bin_name);
	warning("Examples:\n"
		"	%s info ip_send_skb\n"
		"	%s trace ip_send_skb\n"
		"	%s trace \"ip_send_skb(skb, return)\"\n"
		"	%s trace \"ip_send_skb(skb->sk, return)\"\n"
		"	%s trace \"ip_send_skb(skb->len > 128, skb)\"\n"
		"	%s trace -s udp_sendmsg ip_send_skb\n",
		bin_name, bin_name, bin_name, bin_name, bin_name, bin_name);
	return 0;
}

static void usage(void)
{
	cmd_help(0, NULL);
	exit(1);
}

static void type_to_value(struct btf *btf, char *name, __u32 type_id,
			  struct value *val)
{
	const struct btf_type *type;
	__s32 id = type_id;

	if (strlen(val->name) == 0) {
		if (name)
			strncpy(val->name, name,
				sizeof(val->name) - 1);
		else
			val->name[0] = '\0';
	}

	do {
		type = btf__type_by_id(btf, id);

		switch (BTF_INFO_KIND(type->info)) {
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
			id = type->type;
			break;
		case BTF_KIND_PTR:
			val->flags |= KSNOOP_F_PTR;
			id = type->type;
			break;
		default:
			val->type_id = id;
			goto done;
		}
	} while (id >= 0);

	val->type_id = KSNOOP_ID_UNKNOWN;
	return;

done:
	val->size = btf__resolve_size(btf, val->type_id);
}

static int member_to_value(struct btf *btf, const char *name, __u32 type_id,
			   struct value *val, int lvl)
{
	const struct btf_member *member;
	const struct btf_type *type;
	const char *pname;
	__s32 id = type_id;
	int i, nmembers;
	__u8 kind;

	/* type_to_value has already stripped qualifiers, so
	 * we either have a base type, a struct, union, etc.
	 * only struct/unions have named members so anything
	 * else is invalid.
	 */
	pr_debug("Looking for member '%s' in type id %d", name, type_id);
	type = btf__type_by_id(btf, id);
	pname = btf__str_by_offset(btf, type->name_off);
	if (strlen(pname) == 0)
		pname = "<anon>";

	kind = BTF_INFO_KIND(type->info);
	switch (kind) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		nmembers = BTF_INFO_VLEN(type->info);
		pr_debug("Checking %d members...", nmembers);
		for (member = (struct btf_member *)(type + 1), i = 0;
		     i < nmembers;
		     member++, i++) {
			const char *mname;
			__u16 offset;

			type = btf__type_by_id(btf, member->type);
			mname = btf__str_by_offset(btf, member->name_off);
			offset = member->offset / 8;

			pr_debug("Checking member '%s' type %d offset %d",
				 mname, member->type, offset);

			/* anonymous struct member? */
			kind = BTF_INFO_KIND(type->info);
			if (strlen(mname) == 0 &&
			    (kind == BTF_KIND_STRUCT ||
			     kind == BTF_KIND_UNION)) {
				pr_debug("Checking anon struct/union %d",
					 member->type);
				val->offset += offset;
				if (!member_to_value(btf, name, member->type,
						     val, lvl + 1))
					return 0;
				val->offset -= offset;
				continue;
			}

			if (strcmp(mname, name) == 0) {
				val->offset += offset;
				val->flags |= KSNOOP_F_MEMBER;
				type_to_value(btf, NULL, member->type, val);
				pr_debug("Member '%s', offset %d, flags %x size %d",
					 mname, val->offset, val->flags,
					 val->size);
				return 0;
			}
		}
		if (lvl > 0)
			break;
		pr_err("No member '%s' found in %s [%d], offset %d", name, pname,
		       id, val->offset);
		break;
	default:
		pr_err("'%s' is not a struct/union", pname);
		break;
	}
	return -ENOENT;
}
