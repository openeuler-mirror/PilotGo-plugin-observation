/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#ifndef __BPF_TOOL_H
#define __BPF_TOOL_H

/* BFD and kernel.h both define GCC_VERSION, differently */
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

/* Make sure we do not use kernel-only integer typedefs */
