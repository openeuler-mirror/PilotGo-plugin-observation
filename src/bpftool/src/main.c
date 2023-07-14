// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/hashmap.h>
#include <bpf/libbpf.h>

#include "main.h"

#define BATCH_LINE_LEN_MAX 65536
#define BATCH_ARG_NB_MAX 4096

const char *bin_name;
static int last_argc;
static char **last_argv;
static int (*last_do_help)(int argc, char **argv);
json_writer_t *json_wtr;
bool pretty_output;
bool json_output;
bool show_pinned;
bool block_mount;
bool verifier_logs;
bool relaxed_maps;
bool use_loader;
struct btf *base_btf;
struct hashmap *refs_table;

void usage(void)
{
	last_do_help(last_argc - 1, last_argv + 1);

	clean_and_exit(-1);
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %s [OPTIONS] OBJECT { COMMAND | help }\n"
		"       %s batch file FILE\n"
		"       %s version\n"
		"\n"
		"       OBJECT := { prog | map | link | cgroup | perf | net | feature | btf | gen | struct_ops | iter }\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-V|--version} }\n"
		"",
		bin_name, bin_name, bin_name);

	return 0;
}


int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "json",	no_argument,	NULL,	'j' },
		{ "help",	no_argument,	NULL,	'h' },
		{ "pretty",	no_argument,	NULL,	'p' },
		{ "version",	no_argument,	NULL,	'V' },
		{ "bpffs",	no_argument,	NULL,	'f' },
		{ "mapcompat",	no_argument,	NULL,	'm' },
		{ "nomount",	no_argument,	NULL,	'n' },
		{ "debug",	no_argument,	NULL,	'd' },
		{ "use-loader",	no_argument,	NULL,	'L' },
		{ "base-btf",	required_argument, NULL, 'B' },
		{ 0 }
	};
		bool version_requested = false;
	int opt, ret;

	setlinebuf(stdout);

#ifdef USE_LIBCAP
	/* Libcap < 2.63 hooks before main() to compute the number of
	 * capabilities of the running kernel, and doing so it calls prctl()
	 * which may fail and set errno to non-zero.
	 * Let's reset errno to make sure this does not interfere with the
	 * batch mode.
	 */
	errno = 0;
#endif

last_do_help = do_help;
	pretty_output = false;
	json_output = false;
	show_pinned = false;
	block_mount = false;
	bin_name = "bpftool";

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "VhpjfLmndB:l",
				  options, NULL)) >= 0) {
		switch (opt) {
		case 'V':
			version_requested = true;
			break;
		case 'h':
			return do_help(argc, argv);
		case 'p':
			pretty_output = true;
			/* fall through */
					case 'j':
			if (!json_output) {
				json_wtr = jsonw_new(stdout);
				if (!json_wtr) {
					p_err("failed to create JSON writer");
					return -1;
				}
				json_output = true;
			}
			jsonw_pretty(json_wtr, pretty_output);
			break;
		case 'f':
			show_pinned = true;
			break;
		case 'm':
			relaxed_maps = true;
			break;
		case 'n':
			block_mount = true;
			break;
		case 'd':
			libbpf_set_print(print_all_levels);
			verifier_logs = true;
			break;
		case 'B':
			base_btf = btf__parse(optarg, NULL);
			if (!base_btf) {
				p_err("failed to parse base BTF at '%s': %d\n",
				      optarg, -errno);
				return -1;
			}
			break;
	}

	return 0
}
