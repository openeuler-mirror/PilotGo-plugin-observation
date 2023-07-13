// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __KLOCKSTAT_H
#define __KLOCKSTAT_H

#define TASK_COMM_LEN		16
#define PERF_MAX_STACK_DEPTH	127

struct lock_stat {
	__u64 acq_count;
	__u64 acq_total_time;
	__u64 acq_max_time;
	char acq_max_comm[TASK_COMM_LEN];
};

#endif
