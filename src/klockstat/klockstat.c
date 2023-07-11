// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "klockstat.h"
#include "klockstat.skel.h"
#include "trace_helpers.h"
#include "compat.h"
#include <sys/param.h>

static const char args_doc[] = "FUNCTION";
static const char argp_program_doc[] =;

static const struct argp_option opts[] = {
    {}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
}

static void sig_handler(int sig)
{
	exiting = 1;
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
    static struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = argp_program_doc,
	};
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

    if (!bpf_is_root())
		return 1;

    signal(SIGINT, sig_handler);
	libbpf_set_print(libbpf_print_fn);
}