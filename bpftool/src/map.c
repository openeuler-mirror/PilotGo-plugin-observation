// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#include <errno.h>
#include <fcntl.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/hashmap.h>

#include "json_writer.h"
#include "main.h"

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { show | list }   [MAP]\n"
		"       %1$s %2$s create     FILE type TYPE key KEY_SIZE value VALUE_SIZE \\\n"
		"                                  entries MAX_ENTRIES name NAME [flags FLAGS] \\\n"
		"                                  [inner_map MAP] [dev NAME]\n"
		"       %1$s %2$s dump       MAP\n"
		"       %1$s %2$s update     MAP [key DATA] [value VALUE] [UPDATE_FLAGS]\n"
		"       %1$s %2$s lookup     MAP [key DATA]\n"
		"       %1$s %2$s getnext    MAP [key DATA]\n"
		"       %1$s %2$s delete     MAP  key DATA\n"
		"       %1$s %2$s pin        MAP  FILE\n"
		"       %1$s %2$s event_pipe MAP [cpu N index M]\n"
		"       %1$s %2$s peek       MAP\n"
		"       %1$s %2$s push       MAP value VALUE\n"
		"       %1$s %2$s pop        MAP\n"
		"       %1$s %2$s enqueue    MAP value VALUE\n"
		"       %1$s %2$s dequeue    MAP\n"
		"       %1$s %2$s freeze     MAP\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_MAP "\n"
		"       DATA := { [hex] BYTES }\n"
		"       " HELP_SPEC_PROGRAM "\n"
		"       VALUE := { DATA | MAP | PROG }\n"
		"       UPDATE_FLAGS := { any | exist | noexist }\n"
		"       TYPE := { hash | array | prog_array | perf_event_array | percpu_hash |\n"
		"                 percpu_array | stack_trace | cgroup_array | lru_hash |\n"
		"                 lru_percpu_hash | lpm_trie | array_of_maps | hash_of_maps |\n"
		"                 devmap | devmap_hash | sockmap | cpumap | xskmap | sockhash |\n"
		"                 cgroup_storage | reuseport_sockarray | percpu_cgroup_storage |\n"
		"                 queue | stack | sk_storage | struct_ops | ringbuf | inode_storage |\n"
		"                 task_storage | bloom_filter | user_ringbuf | cgrp_storage }\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-f|--bpffs} | {-n|--nomount} }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "help",	do_help },
	{ "dump",	do_dump },
	{ "update",	do_update },
	{ "lookup",	do_lookup },
	{ "getnext",	do_getnext },
	{ "delete",	do_delete },
	{ "pin",	do_pin },
	{ "event_pipe",	do_event_pipe },
	{ "create",	do_create },
	{ "peek",	do_lookup },
	{ "push",	do_update },
	{ "enqueue",	do_update },
	{ "pop",	do_pop_dequeue },
	{ "dequeue",	do_pop_dequeue },
	{ "freeze",	do_freeze },
	{ 0 }
};

int do_map(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
