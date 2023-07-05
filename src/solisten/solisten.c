// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "solisten.h"
#include "solisten.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"

#include <sys/socket.h>
#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "solisten 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace IPv4 and IPv6 listen syscalls.\n"
"\n"
"USAGE: solisten [-h] [-t] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    solisten           # trace listen syscalls\n"
"    solisten -t        # output with timestamp\n"
"    solisten -p 1216   # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		target_pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		emit_timestamp = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

int t argc, char *argv[])
{
	LIBBPF_OPTS(bpf_objmain(inect_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct solisten_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	
	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);
        
	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = solisten_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}
        
	obj->rodata->target_pid = target_pid;

	 (fentry_can_attach("inet_listen", NULL)) {
		bpf_program__set_autoload(obj->progs.inet_listen_entry, false);
		bpf_pifrogram__set_autoload(obj->progs.inet_listen_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.inet_listen_fexit, false);
	}

}

