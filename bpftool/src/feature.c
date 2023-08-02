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

enum probe_component {
	COMPONENT_UNSPEC,
	COMPONENT_KERNEL,
	COMPONENT_DEVICE,
};

#define BPF_HELPER_MAKE_ENTRY(name)	[BPF_FUNC_ ## name] = "bpf_" # name
static const char * const helper_name[] = {
	__BPF_FUNC_MAPPER(BPF_HELPER_MAKE_ENTRY)
};

#undef BPF_HELPER_MAKE_ENTRY

static bool full_mode;
#ifdef USE_LIBCAP
static bool run_as_unprivileged;
#endif

/* Miscellaneous utility functions */

static bool grep(const char *buffer, const char *pattern)
{
	return !!strstr(buffer, pattern);
}

static bool check_procfs(void)
{
	struct statfs st_fs;

	if (statfs("/proc", &st_fs) < 0)
		return false;
	if ((unsigned long)st_fs.f_type != PROC_SUPER_MAGIC)
		return false;

	return true;
}

static void uppercase(char *str, size_t len)
{
	size_t i;

	for (i = 0; i < len && str[i] != '\0'; i++)
		str[i] = toupper(str[i]);
}

/* Printing utility functions */

static void
print_bool_feature(const char *feat_name, const char *plain_name,
		   const char *define_name, bool res, const char *define_prefix)
{
	if (json_output)
		jsonw_bool_field(json_wtr, feat_name, res);
	else if (define_prefix)
		printf("#define %s%sHAVE_%s\n", define_prefix,
		       res ? "" : "NO_", define_name);
	else
		printf("%s is %savailable\n", plain_name, res ? "" : "NOT ");
}

static void print_kernel_option(const char *name, const char *value,
				const char *define_prefix)
{
	char *endptr;
	int res;

	if (json_output) {
		if (!value) {
			jsonw_null_field(json_wtr, name);
			return;
		}
		errno = 0;
		res = strtol(value, &endptr, 0);
		if (!errno && *endptr == '\n')
			jsonw_int_field(json_wtr, name, res);
		else
			jsonw_string_field(json_wtr, name, value);
	} else if (define_prefix) {
		if (value)
			printf("#define %s%s %s\n", define_prefix,
			       name, value);
		else
			printf("/* %s%s is not set */\n", define_prefix, name);
	} else {
		if (value)
			printf("%s is set to %s\n", name, value);
		else
			printf("%s is not set\n", name);
	}
}

static void
print_start_section(const char *json_title, const char *plain_title,
		    const char *define_comment, const char *define_prefix)
{
	if (json_output) {
		jsonw_name(json_wtr, json_title);
		jsonw_start_object(json_wtr);
	} else if (define_prefix) {
		printf("%s\n", define_comment);
	} else {
		printf("%s\n", plain_title);
	}
}

static void print_end_section(void)
{
	if (json_output)
		jsonw_end_object(json_wtr);
	else
		printf("\n");
}

/* Probing functions */

static int get_vendor_id(int ifindex)
{
	char ifname[IF_NAMESIZE], path[64], buf[8];
	ssize_t len;
	int fd;

	if (!if_indextoname(ifindex, ifname))
		return -1;

	snprintf(path, sizeof(path), "/sys/class/net/%s/device/vendor", ifname);

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len < 0)
		return -1;
	if (len >= (ssize_t)sizeof(buf))
		return -1;
	buf[len] = '\0';

	return strtol(buf, NULL, 0);
}

static int read_procfs(const char *path)
{
	char *endptr, *line = NULL;
	size_t len = 0;
	FILE *fd;
	int res;

	fd = fopen(path, "r");
	if (!fd)
		return -1;

	res = getline(&line, &len, fd);
	fclose(fd);
	if (res < 0)
		return -1;

	errno = 0;
	res = strtol(line, &endptr, 10);
	if (errno || *line == '\0' || *endptr != '\n')
		res = -1;
	free(line);

	return res;
}

static void probe_unprivileged_disabled(void)
{
	int res;

	/* No support for C-style ouptut */

	res = read_procfs("/proc/sys/kernel/unprivileged_bpf_disabled");
	if (json_output) {
		jsonw_int_field(json_wtr, "unprivileged_bpf_disabled", res);
	} else {
		switch (res) {
		case 0:
			printf("bpf() syscall for unprivileged users is enabled\n");
			break;
		case 1:
			printf("bpf() syscall restricted to privileged users (without recovery)\n");
			break;
		case 2:
			printf("bpf() syscall restricted to privileged users (admin can change)\n");
			break;
		case -1:
			printf("Unable to retrieve required privileges for bpf() syscall\n");
			break;
		default:
			printf("bpf() syscall restriction has unknown value %d\n", res);
		}
	}
}

static void probe_jit_enable(void)
{
	int res;

	/* No support for C-style ouptut */

	res = read_procfs("/proc/sys/net/core/bpf_jit_enable");
	if (json_output) {
		jsonw_int_field(json_wtr, "bpf_jit_enable", res);
	} else {
		switch (res) {
		case 0:
			printf("JIT compiler is disabled\n");
			break;
		case 1:
			printf("JIT compiler is enabled\n");
			break;
		case 2:
			printf("JIT compiler is enabled with debugging traces in kernel logs\n");
			break;
		case -1:
			printf("Unable to retrieve JIT-compiler status\n");
			break;
		default:
			printf("JIT-compiler status has unknown value %d\n",
			       res);
		}
	}
}


static void
section_system_config(enum probe_component target, const char *define_prefix)
{
	switch (target) {
	case COMPONENT_KERNEL:
	case COMPONENT_UNSPEC:
		print_start_section("system_config",
				    "Scanning system configuration...",
				    "/*** Misc kernel config items ***/",
				    define_prefix);
		if (!define_prefix) {
			if (check_procfs()) {
				probe_unprivileged_disabled();
				probe_jit_enable();
				probe_jit_harden();
				probe_jit_kallsyms();
				probe_jit_limit();
			} else {
				p_info("/* procfs not mounted, skipping related probes */");
			}
		}
		probe_kernel_image_config(define_prefix);
		print_end_section();
		break;
	default:
		break;
	}
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

static int do_list_builtins(int argc, char **argv)
{
	const char *(*get_name)(unsigned int id);
	unsigned int id = 0;

	if (argc < 1)
		usage();

	if (is_prefix(*argv, "prog_types")) {
		get_name = (const char *(*)(unsigned int))libbpf_bpf_prog_type_str;
	} else if (is_prefix(*argv, "map_types")) {
		get_name = (const char *(*)(unsigned int))libbpf_bpf_map_type_str;
	} else if (is_prefix(*argv, "attach_types")) {
		get_name = (const char *(*)(unsigned int))libbpf_bpf_attach_type_str;
	} else if (is_prefix(*argv, "link_types")) {
		get_name = (const char *(*)(unsigned int))libbpf_bpf_link_type_str;
	} else if (is_prefix(*argv, "helpers")) {
		get_name = get_helper_name;
	} else {
		p_err("expected 'prog_types', 'map_types', 'attach_types', 'link_types' or 'helpers', got: %s", *argv);
		return -1;
	}

	if (json_output)
		jsonw_start_array(json_wtr);

	while (true) {
		const char *name;

		name = get_name(id++);
		if (!name)
			break;
		if (json_output)
			jsonw_string(json_wtr, name);
		else
			printf("%s\n", name);
	}

	if (json_output)
		jsonw_end_array(json_wtr);

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
