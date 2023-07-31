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

	/* Full feature detection requires specific privileges.
	 * Let's approximate, and warn if user is not root.
	 */
	if (handle_perms())
		return -1;

	if (json_output) {
		define_prefix = NULL;
		jsonw_start_object(json_wtr);
	}

	section_system_config(target, define_prefix);
	if (!section_syscall_config(define_prefix))
		/* bpf() syscall unavailable, don't probe other BPF features */
		goto exit_close_json;
	section_program_types(supported_types, define_prefix, ifindex);
	section_map_types(define_prefix, ifindex);
	section_helpers(supported_types, define_prefix, ifindex);
	section_misc(define_prefix, ifindex);

exit_close_json:
	if (json_output)
		/* End root object */
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
