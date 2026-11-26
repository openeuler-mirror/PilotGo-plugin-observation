// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "biopattern.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile bool filter_dev = false;
const volatile __u32 target_dev = 0;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct counter);
} counters SEC(".maps");

static __always_inline void read_completion_args(void *args, sector_t *sector,
						 u32 *nr_sector, u32 *dev)
{
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 18, 0)) {
		struct trace_event_raw_block_rq_completion___x *ctx = args;

		*sector = BPF_CORE_READ(ctx, sector);
		*nr_sector = BPF_CORE_READ(ctx, nr_sector);
		*dev = BPF_CORE_READ(ctx, dev);
	} else {
		struct trace_event_raw_block_rq_complete___x *ctx = args;

		*sector = BPF_CORE_READ(ctx, sector);
		*nr_sector = BPF_CORE_READ(ctx, nr_sector);
		*dev = BPF_CORE_READ(ctx, dev);
	}
}

static __always_inline void account_sector(struct counter *counter,
					   sector_t sector, u32 nr_sector)
{
	if (counter->last_sector) {
		if (counter->last_sector == sector)
			__sync_fetch_and_add(&counter->sequential, 1);
		else
			__sync_fetch_and_add(&counter->random, 1);
		__sync_fetch_and_add(&counter->bytes, nr_sector << 9);
	}
	counter->last_sector = sector + nr_sector;
}

SEC("tracepoint/block/block_rq_complete")
static void handle__block_rq_complete_extra(void)
{
		struct counter *counterp, zero = {};
		sector_t sector;
		u32 nr_sector;
		u32 dev;
		read_completion_args(args, &sector, &nr_sector, &dev);
		if (filter_dev && target_dev != dev)
			return 0;
		counterp = bpf_map_lookup_or_try_init(&counters, &dev, &zero);
		if (!counterp)
			return 0;
		account_sector(counterp, sector, nr_sector);
		return 0;
}

int handle__block_rq_complete(void *args)
{
	handle__block_rq_complete_extra();
}

char LICENSE[] SEC("license") = "GPL";
