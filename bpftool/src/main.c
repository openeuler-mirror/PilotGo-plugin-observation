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

static void __noreturn clean_and_exit(int i)
{
	if (json_output)
		jsonw_destroy(&json_wtr);

	exit(i);
}

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


static int do_version(int argc, char **argv);

static const struct cmd commands[] = {
	{ "help",	do_help },
	{ "batch",	do_batch },
	{ "prog",	do_prog },
	{ "map",	do_map },
	{ "link",	do_link },
	{ "cgroup",	do_cgroup },
};

#ifndef BPFTOOL_VERSION
#define BPFTOOL_MAJOR_VERSION (LIBBPF_MAJOR_VERSION + 6)
#define BPFTOOL_MINOR_VERSION LIBBPF_MINOR_VERSION
#define BPFTOOL_PATCH_VERSION 0
#endif

static int do_version(int argc, char **argv)
{
#ifdef HAVE_LIBBFD_SUPPORT
	const bool has_libbfd = true;
#else
	const bool has_libbfd = false;
#endif
#ifdef HAVE_LLVM_SUPPORT
	const bool has_llvm = true;
#else
	const bool has_llvm = false;
#endif
#ifdef BPFTOOL_WITHOUT_SKELETONS
	const bool has_skeletons = false;
#else
	const bool has_skeletons = true;
#endif
	bool bootstrap = false;
	int i;

	for (i = 0; commands[i].cmd; i++) {
		if (!strcmp(commands[i].cmd, "prog")) {
			bootstrap = !commands[i].func;
			break;
		}
	}

	if (json_output) {
		jsonw_start_object(json_wtr);

		jsonw_name(json_wtr, "version");
#ifdef BPFTOOL_VERSION
		jsonw_printf(json_wtr, "\"%s\"", BPFTOOL_VERSION);
#else
		jsonw_printf(json_wtr, "\"%d.%d.%d\"", BPFTOOL_MAJOR_VERSION,
			     BPFTOOL_MINOR_VERSION, BPFTOOL_PATCH_VERSION);
#endif
		jsonw_name(json_wtr, "libbpf_version");
		jsonw_printf(json_wtr, "\"%d.%d\"",
			     libbpf_major_version(), libbpf_minor_version());

		jsonw_name(json_wtr, "features");
		jsonw_start_object(json_wtr);
		jsonw_bool_field(json_wtr, "libbfd", has_libbfd);
		jsonw_bool_field(json_wtr, "llvm", has_llvm);
		jsonw_bool_field(json_wtr, "skeletons", has_skeletons);
		jsonw_bool_field(json_wtr, "bootstrap", bootstrap);
		jsonw_end_object(json_wtr);	/* features */

		jsonw_end_object(json_wtr);	/* root object */
	} else {
		unsigned int nb_features = 0;

#ifdef BPFTOOL_VERSION
		printf("%s v%s\n", bin_name, BPFTOOL_VERSION);
#else
		printf("%s v%d.%d.%d\n", bin_name, BPFTOOL_MAJOR_VERSION,
		       BPFTOOL_MINOR_VERSION, BPFTOOL_PATCH_VERSION);
#endif
		printf("using libbpf %s\n", libbpf_version_string());
		printf("features:");
		print_feature("libbfd", has_libbfd, &nb_features);
		print_feature("llvm", has_llvm, &nb_features);
		print_feature("skeletons", has_skeletons, &nb_features);
		print_feature("bootstrap", bootstrap, &nb_features);
		printf("\n");
	}
	return 0;
}

bool is_prefix(const char *pfx, const char *str)
{
	if (!pfx)
		return false;
	if (strlen(str) < strlen(pfx))
		return false;

	return !memcmp(str, pfx, strlen(pfx));
}

int detect_common_prefix(const char *arg, ...)
{
	unsigned int count = 0;
	const char *ref;
	char msg[256];
	va_list ap;

	snprintf(msg, sizeof(msg), "ambiguous prefix: '%s' could be '", arg);
	va_start(ap, arg);
	while ((ref = va_arg(ap, const char *))) {
		if (!is_prefix(arg, ref))
			continue;
		count++;
		if (count > 1)
			strncat(msg, "' or '", sizeof(msg) - strlen(msg) - 1);
		strncat(msg, ref, sizeof(msg) - strlen(msg) - 1);
	}
	va_end(ap);
	strncat(msg, "'", sizeof(msg) - strlen(msg) - 1);

	if (count >= 2) {
		p_err("%s", msg);
		return -1;
	}

	return 0;
}

int cmd_select(const struct cmd *cmds, int argc, char **argv,
	       int (*help)(int argc, char **argv))
{
	unsigned int i;

	last_argc = argc;
	last_argv = argv;
	last_do_help = help;

	if (argc < 1 && cmds[0].func)
		return cmds[0].func(argc, argv);

	for (i = 0; cmds[i].cmd; i++) {
		if (is_prefix(*argv, cmds[i].cmd)) {
			if (!cmds[i].func) {
				p_err("command '%s' is not supported in bootstrap mode",
				      cmds[i].cmd);
				return -1;
			}
			return cmds[i].func(argc - 1, argv + 1);
		}
	}

	help(argc - 1, argv + 1);

	return -1;
}

static int do_batch(int argc, char **argv)
{
	char buf[BATCH_LINE_LEN_MAX], contline[BATCH_LINE_LEN_MAX];
	char *n_argv[BATCH_ARG_NB_MAX];
	unsigned int lines = 0;
	int n_argc;
	FILE *fp;
	char *cp;
	int err = 0;
	int i;

	if (argc < 2) {
		p_err("too few parameters for batch");
		return -1;
	} else if (argc > 2) {
		p_err("too many parameters for batch");
		return -1;
	} else if (!is_prefix(*argv, "file")) {
		p_err("expected 'file', got: %s", *argv);
		return -1;
	}
	NEXT_ARG();

	if (!strcmp(*argv, "-"))
		fp = stdin;
	else
		fp = fopen(*argv, "r");
	if (!fp) {
		p_err("Can't open file (%s): %s", *argv, strerror(errno));
		return -1;
	}

	if (json_output)
		jsonw_start_array(json_wtr);
	
	return err;
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
		case 'L':
			use_loader = true;
			break;
		default:
			p_err("unrecognized option '%s'", argv[optind - 1]);
			if (json_output)
				clean_and_exit(-1);
			else
				usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 0)
		usage();
	if (version_requested)
		return do_version(argc, argv);

	ret = cmd_select(commands, argc, argv, do_help);
	
	return 0
}
