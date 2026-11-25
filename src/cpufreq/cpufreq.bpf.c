// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cpufreq.h"
#include "maps.bpf.h"

__u32 freqs_mhz[MAX_CPU_NR] = {};
static struct hist zero;
struct hist syswide = {};
bool filter_memcg = false;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hkey);
	__type(value, struct hist);
} hists SEC(".maps");

static __always_inline bool memcg_filtered(void)
{
	return filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0);
}

static __always_inline int probe_cpu_frequency(unsigned int state, unsigned int cpu_id)
{
	if (memcg_filtered())
		return 0;

	if (cpu_id >= MAX_CPU_NR)
		return 0;

	freqs_mhz[cpu_id] = state / 1000;
	return 0;
}

static __always_inline __u64 freq_slot(__u32 freq_mhz)
{
	__u64 slot;

	/*
	 * The range of the linear histogram is 0 ~ 5000mhz,
	 * and the step size is 200.
	 */
	slot = freq_mhz / HIST_STEP_SIZE;
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	return slot;
}

static __always_inline void account_process_freq(__u32 pid, __u64 slot)
{
	struct hkey hkey = {};
	struct hist *hist;

	if (!pid)
		return;

	bpf_get_current_comm(&hkey.comm, sizeof(hkey.comm));
	hist = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
	if (!hist)
		return;

	__sync_fetch_and_add(&hist->slots[slot], 1);
}

SEC("tp_btf/cpu_frequency")
int BPF_PROG(cpu_frequency, unsigned int state, unsigned int cpu_id)
{
	return probe_cpu_frequency(state, cpu_id);
}

SEC("raw_tp/cpu_frequency_raw")
int BPF_PROG(cpu_frequency_raw, unsigned int state, unsigned int cpu_id)
{
	return probe_cpu_frequency(state, cpu_id);
}

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	u32 freq_mhz, pid = bpf_get_current_pid_tgid();
	u64 slot, cpu = bpf_get_smp_processor_id();

	if (memcg_filtered())
		return 0;

	if (cpu >= MAX_CPU_NR)
		return 0;

	freq_mhz = freqs_mhz[cpu];
	if (!freq_mhz)
		return 0;

	slot = freq_slot(freq_mhz);
	__sync_fetch_and_add(&syswide.slots[slot], 1);

	account_process_freq(pid, slot);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
