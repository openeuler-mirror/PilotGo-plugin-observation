// SPDX-License-Identifier: GPL-2.0
#include "commons.h"
#include "tcptracer.h"
#include "tcptracer.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "compat.h"

#include <sys/resource.h>
#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcptracer 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\ntcptracer: Trace TCP connections\n"
"\n"
"EXAMPLES:\n"
"    tcptracer             # trace all TCP connections\n"
"    tcptracer -t          # include timestamps\n"
"    tcptracer -p 181      # only trace PID 181\n"
"    tcptracer -U          # include UID\n"
"    tcptracer -u 1000     # only trace UID 1000\n"
"    tcptracer --C mappath # only trace cgroups in the map\n"
"    tcptracer --M mappath # only trace mount namespaces in the map\n";

static int get_uint(const char *arg, unsigned int *ret, unsigned int min,
		    unsigned int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtoul(arg, &end, 10);
	if (errno) {
		warning("strtoul: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "print-uid", 'U', NULL, 0, "Include UID on output" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "uid", 'u', "UID", 0, "Process UID to trace" },
	{ "cgroupmap", 'C', "PATH", 0, "trace cgroups in this map" },
	{ "mntnsmap", 'M', "PATH", 0, "trace mount namespaces in this map" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static struct env {
	bool verbose;
	bool count;
	bool print_timestamp;
	bool print_uid;
	pid_t pid;
	uid_t uid;
} env = {
	.uid = (uid_t)-1
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'c':
		env.count = true;
		break;
	case 't':
		env.print_timestamp = true;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'u':
		if (get_uint(arg, &env.uid, 0, (uid_t)-2)) {
			warning("Invalid UID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'C':
		warning("Not implemented: --cgroupmap\n");
		break;
	case 'M':
		warning("Not implemented: --mntnsmap\n");
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc
	};
	struct tcptracer_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
		
        if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	return err != 0;
}
