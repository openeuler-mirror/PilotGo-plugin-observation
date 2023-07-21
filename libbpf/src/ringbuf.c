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

static void ringbuf_unmap_ring(struct ring_buffer *rb, struct ring *r)
{
	if (r->consumer_pos) {
		munmap(r->consumer_pos, rb->page_size);
		r->consumer_pos = NULL;
	}
	if (r->producer_pos) {
		munmap(r->producer_pos, rb->page_size + 2 * (r->mask + 1));
		r->producer_pos = NULL;
	}
}

/* Add extra RINGBUF maps to this ring buffer manager */
int ring_buffer__add(struct ring_buffer *rb, int map_fd,
		     ring_buffer_sample_fn sample_cb, void *ctx)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	struct epoll_event *e;
	struct ring *r;
	__u64 mmap_sz;
	void *tmp;
	int err;

	memset(&info, 0, sizeof(info));

	err = bpf_map_get_info_by_fd(map_fd, &info, &len);
	if (err) {
		err = -errno;
		pr_warn("ringbuf: failed to get map info for fd=%d: %d\n",
			map_fd, err);
		return libbpf_err(err);
	}

	if (info.type != BPF_MAP_TYPE_RINGBUF) {
		pr_warn("ringbuf: map fd=%d is not BPF_MAP_TYPE_RINGBUF\n",
			map_fd);
		return libbpf_err(-EINVAL);
	}

	tmp = libbpf_reallocarray(rb->rings, rb->ring_cnt + 1, sizeof(*rb->rings));
	if (!tmp)
		return libbpf_err(-ENOMEM);
	rb->rings = tmp;

	tmp = libbpf_reallocarray(rb->events, rb->ring_cnt + 1, sizeof(*rb->events));
	if (!tmp)
		return libbpf_err(-ENOMEM);
	rb->events = tmp;

	r = &rb->rings[rb->ring_cnt];
	memset(r, 0, sizeof(*r));

	r->map_fd = map_fd;
	r->sample_cb = sample_cb;
	r->ctx = ctx;
	r->mask = info.max_entries - 1;

	/* Map writable consumer page */
	tmp = mmap(NULL, rb->page_size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (tmp == MAP_FAILED) {
		err = -errno;
		pr_warn("ringbuf: failed to mmap consumer page for map fd=%d: %d\n",
			map_fd, err);
		return libbpf_err(err);
	}
	r->consumer_pos = tmp;

	/* Map read-only producer page and data pages. We map twice as big
	 * data size to allow simple reading of samples that wrap around the
	 * end of a ring buffer. See kernel implementation for details.
	 */
	mmap_sz = rb->page_size + 2 * (__u64)info.max_entries;
	if (mmap_sz != (__u64)(size_t)mmap_sz) {
		pr_warn("ringbuf: ring buffer size (%u) is too big\n", info.max_entries);
		return libbpf_err(-E2BIG);
	}
	tmp = mmap(NULL, (size_t)mmap_sz, PROT_READ, MAP_SHARED, map_fd, rb->page_size);
	if (tmp == MAP_FAILED) {
		err = -errno;
		ringbuf_unmap_ring(rb, r);
		pr_warn("ringbuf: failed to mmap data pages for map fd=%d: %d\n",
			map_fd, err);
		return libbpf_err(err);
	}
	r->producer_pos = tmp;
	r->data = tmp + rb->page_size;

	e = &rb->events[rb->ring_cnt];
	memset(e, 0, sizeof(*e));

	e->events = EPOLLIN;
	e->data.fd = rb->ring_cnt;
	if (epoll_ctl(rb->epoll_fd, EPOLL_CTL_ADD, map_fd, e) < 0) {
		err = -errno;
		ringbuf_unmap_ring(rb, r);
		pr_warn("ringbuf: failed to epoll add map fd=%d: %d\n",
			map_fd, err);
		return libbpf_err(err);
	}

	rb->ring_cnt++;
	return 0;
}

void ring_buffer__free(struct ring_buffer *rb)
{
	int i;

	if (!rb)
		return;

	for (i = 0; i < rb->ring_cnt; ++i)
		ringbuf_unmap_ring(rb, &rb->rings[i]);
	if (rb->epoll_fd >= 0)
		close(rb->epoll_fd);

	free(rb->events);
	free(rb->rings);
	free(rb);
}

struct ring_buffer *
ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx,
		 const struct ring_buffer_opts *opts)
{
	struct ring_buffer *rb;
	int err;

	if (!OPTS_VALID(opts, ring_buffer_opts))
		return errno = EINVAL, NULL;

	rb = calloc(1, sizeof(*rb));
	if (!rb)
		return errno = ENOMEM, NULL;

	rb->page_size = getpagesize();

	rb->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (rb->epoll_fd < 0) {
		err = -errno;
		pr_warn("ringbuf: failed to create epoll instance: %d\n", err);
		goto err_out;
	}

	err = ring_buffer__add(rb, map_fd, sample_cb, ctx);
	if (err)
		goto err_out;

	return rb;

err_out:
	ring_buffer__free(rb);
	return errno = -err, NULL;
}

