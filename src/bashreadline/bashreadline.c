// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "bashreadline.h"
#include "bashreadline.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

static volatile sig_atomic_t exiting;

const char *argp_program_version = "bashreadline 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Print entered bash commands from all running shells.\n"
"\n"
"USAGE: bashreadline [-s <path/to/libreadline.so>]\n"
"\n"
"EXAMPLES:\n"
"    bashreadline\n"
"    bashreadline -s /usr/lib/libreadline.so\n";

static const struct argp_option opts[] = {
	{ "shared", 's', "PATH", 0, "the location of libreadline.so library" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static struct env {
	char *libreadline_path;
	bool verbose;
} env = {};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 's':
		if (!arg)
			return ARGP_ERR_UNKNOWN;
		env.libreadline_path = strdup(arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}



int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct bashreadline_bpf *obj;
	struct perf_buffer *pb = NULL;
	char *readline_so_path;
	off_t func_off;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if (env.libreadline_path) {
		readline_so_path = env.libreadline_path;
	} else {
		const char *bash_path = "/bin/bash";

		if (get_elf_func_offset(bash_path, "readline") >= 0)
			readline_so_path = strdup(bash_path);
		else {
			readline_so_path = find_library_so(bash_path, "/libreadline.so");
			if (!readline_so_path) {
				warning("Failed to find readline\n");
				return 1;
			}
		}
	}

	return err != 0;
}