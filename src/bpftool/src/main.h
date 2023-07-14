#ifndef __BPF_TOOL_H
#define __BPF_TOOL_H

#undef GCC_VERSION
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/compiler.h>
#include <linux/kernel.h>

#include <bpf/hashmap.h>
#include <bpf/libbpf.h>

#include "json_writer.h"


void usage(void) __noreturn;

int print_all_levels(__maybe_unused enum libbpf_print_level level,
		     const char *format, va_list args);




struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
};
