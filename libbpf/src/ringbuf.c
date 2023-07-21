// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Ring buffer operations.
 *
 * Copyright (C) 2020 Facebook, Inc.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <linux/err.h>
#include <linux/bpf.h>
#include <asm/barrier.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <time.h>

#include "libbpf.h"
#include "libbpf_internal.h"
#include "bpf.h"

struct ring {
	ring_buffer_sample_fn sample_cb;
	void *ctx;
	void *data;
	unsigned long *consumer_pos;
	unsigned long *producer_pos;
	unsigned long mask;
	int map_fd;
};

struct ring_buffer {
	struct epoll_event *events;
	struct ring *rings;
	size_t page_size;
	int epoll_fd;
	int ring_cnt;
};

struct user_ring_buffer {
	struct epoll_event event;
	unsigned long *consumer_pos;
	unsigned long *producer_pos;
	void *data;
	unsigned long mask;
	size_t page_size;
	int map_fd;
	int epoll_fd;
};

/* 8-byte ring buffer header structure */
struct ringbuf_hdr {
	__u32 len;
	__u32 pad;
};
