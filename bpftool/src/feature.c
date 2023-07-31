#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#ifdef USE_LIBCAP
#include <sys/capability.h>
#endif
#include <sys/utsname.h>
#include <sys/vfs.h>

#include <linux/filter.h>
#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <zlib.h>

#include "main.h"

#ifndef PROC_SUPER_MAGIC
# define PROC_SUPER_MAGIC	0x9fa0
#endif

void set_max_rlimit(void)
{
	struct rlimit rinf = { RLIM_INFINITY, RLIM_INFINITY };

	if (known_to_need_rlimit())
		setrlimit(RLIMIT_MEMLOCK, &rinf);
}

#ifdef USE_LIBCAP
#define capability(c) { c, false, #c }
#define capability_msg(a, i) a[i].set ? "" : a[i].name, a[i].set ? "" : ", "
#endif

static int handle_perms(void)
{
#ifdef USE_LIBCAP
	struct {
		cap_value_t cap;
		bool set;
		char name[14];	/* strlen("CAP_SYS_ADMIN") */
	} bpf_caps[] = {
		capability(CAP_SYS_ADMIN),
#ifdef CAP_BPF
		capability(CAP_BPF),
		capability(CAP_NET_ADMIN),
		capability(CAP_PERFMON),
#endif
	};
	cap_value_t cap_list[ARRAY_SIZE(bpf_caps)];
	unsigned int i, nb_bpf_caps = 0;
	bool cap_sys_admin_only = true;
	cap_flag_value_t val;
	int res = -1;
	cap_t caps;

	caps = cap_get_proc();
	if (!caps) {
		p_err("failed to get capabilities for process: %s",
		      strerror(errno));
		return -1;
	}

#ifdef CAP_BPF
	if (CAP_IS_SUPPORTED(CAP_BPF))
		cap_sys_admin_only = false;
#endif

	for (i = 0; i < ARRAY_SIZE(bpf_caps); i++) {
		const char *cap_name = bpf_caps[i].name;
		cap_value_t cap = bpf_caps[i].cap;

		if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &val)) {
			p_err("bug: failed to retrieve %s status: %s", cap_name,
			      strerror(errno));
			goto exit_free;
		}

		if (val == CAP_SET) {
			bpf_caps[i].set = true;
			cap_list[nb_bpf_caps++] = cap;
		}

		if (cap_sys_admin_only)
			break;
	}

	if ((run_as_unprivileged && !nb_bpf_caps) ||
	    (!run_as_unprivileged && nb_bpf_caps == ARRAY_SIZE(bpf_caps)) ||
	    (!run_as_unprivileged && cap_sys_admin_only && nb_bpf_caps)) {
		/* We are all good, exit now */
		res = 0;
		goto exit_free;
	}

	if (!run_as_unprivileged) {
		if (cap_sys_admin_only)
			p_err("missing %s, required for full feature probing; run as root or use 'unprivileged'",
			      bpf_caps[0].name);
		else
			p_err("missing %s%s%s%s%s%s%s%srequired for full feature probing; run as root or use 'unprivileged'",
			      capability_msg(bpf_caps, 0),
#ifdef CAP_BPF
			      capability_msg(bpf_caps, 1),
			      capability_msg(bpf_caps, 2),
			      capability_msg(bpf_caps, 3)
#else
				"", "", "", "", "", ""
#endif /* CAP_BPF */
				);
		goto exit_free;
	}

	if (cap_set_flag(caps, CAP_EFFECTIVE, nb_bpf_caps, cap_list,
			 CAP_CLEAR)) {
		p_err("bug: failed to clear capabilities: %s", strerror(errno));
		goto exit_free;
	}

	if (cap_set_proc(caps)) {
		p_err("failed to drop capabilities: %s", strerror(errno));
		goto exit_free;
	}

	res = 0;

exit_free:
	if (cap_free(caps) && !res) {
		p_err("failed to clear storage object for capabilities: %s",
		      strerror(errno));
		res = -1;
	}

	return res;
#else
	if (geteuid()) {
		p_err("full feature probing requires root privileges");
		return -1;
	}

	return 0;
#endif
}

static int do_probe(int argc, char **argv)
{
	enum probe_component target = COMPONENT_UNSPEC;
	const char *define_prefix = NULL;
	bool supported_types[128] = {};
	__u32 ifindex = 0;
	char *ifname;

	set_max_rlimit();

	while (argc) {
		if (is_prefix(*argv, "kernel")) {
			if (target != COMPONENT_UNSPEC) {
				p_err("component to probe already specified");
				return -1;
			}
			target = COMPONENT_KERNEL;
			NEXT_ARG();
		} else if (is_prefix(*argv, "dev")) {
			NEXT_ARG();

			if (target != COMPONENT_UNSPEC || ifindex) {
				p_err("component to probe already specified");
				return -1;
			}
			if (!REQ_ARGS(1))
				return -1;

			target = COMPONENT_DEVICE;
			ifname = GET_ARG();
			ifindex = if_nametoindex(ifname);
			if (!ifindex) {
				p_err("unrecognized netdevice '%s': %s", ifname,
				      strerror(errno));
				return -1;
			}
		} else if (is_prefix(*argv, "full")) {
			full_mode = true;
			NEXT_ARG();
		} else if (is_prefix(*argv, "macros") && !define_prefix) {
			define_prefix = "";
			NEXT_ARG();
		} else if (is_prefix(*argv, "prefix")) {
			if (!define_prefix) {
				p_err("'prefix' argument can only be use after 'macros'");
				return -1;
			}
			if (strcmp(define_prefix, "")) {
				p_err("'prefix' already defined");
				return -1;
			}
			NEXT_ARG();

			if (!REQ_ARGS(1))
				return -1;
			define_prefix = GET_ARG();
		} else if (is_prefix(*argv, "unprivileged")) {
#ifdef USE_LIBCAP
			run_as_unprivileged = true;
			NEXT_ARG();
#else
			p_err("unprivileged run not supported, recompile bpftool with libcap");
			return -1;
#endif
		} else {
			p_err("expected no more arguments, 'kernel', 'dev', 'macros' or 'prefix', got: '%s'?",
			      *argv);
			return -1;
		}
	}

	if (handle_perms())
		return -1;

	if (json_output) {
		define_prefix = NULL;
		jsonw_start_object(json_wtr);
	}

	section_system_config(target, define_prefix);
	if (!section_syscall_config(define_prefix))
		goto exit_close_json;
	section_program_types(supported_types, define_prefix, ifindex);
	section_map_types(define_prefix, ifindex);
	section_helpers(supported_types, define_prefix, ifindex);
	section_misc(define_prefix, ifindex);

exit_close_json:
	if (json_output)
		jsonw_end_object(json_wtr);

	return 0;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s probe [COMPONENT] [full] [unprivileged] [macros [prefix PREFIX]]\n"
		"       %1$s %2$s list_builtins GROUP\n"
		"       %1$s %2$s help\n"
		"\n"
		"       COMPONENT := { kernel | dev NAME }\n"
		"       GROUP := { prog_types | map_types | attach_types | link_types | helpers }\n"
		"       " HELP_SPEC_OPTIONS " }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "probe",		do_probe },
	{ "list_builtins",	do_list_builtins },
	{ "help",		do_help },
	{ 0 }
};

int do_feature(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
