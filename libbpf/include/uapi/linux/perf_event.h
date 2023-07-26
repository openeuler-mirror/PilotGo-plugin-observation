/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Performance events:
 *
 *    Copyright (C) 2008-2009, Thomas Gleixner <tglx@linutronix.de>
 *    Copyright (C) 2008-2011, Red Hat, Inc., Ingo Molnar
 *    Copyright (C) 2008-2011, Red Hat, Inc., Peter Zijlstra
 *
 * Data type definitions, declarations, prototypes.
 *
 *    Started by: Thomas Gleixner and Ingo Molnar
 *
 * For licencing details see kernel-base/COPYING
 */
#ifndef _UAPI_LINUX_PERF_EVENT_H
#define _UAPI_LINUX_PERF_EVENT_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <asm/byteorder.h>

/*
 * User-space ABI bits:
 */

/*
 * attr.type
 */
enum perf_type_id {
	PERF_TYPE_HARDWARE			= 0,
	PERF_TYPE_SOFTWARE			= 1,
	PERF_TYPE_TRACEPOINT			= 2,
	PERF_TYPE_HW_CACHE			= 3,
	PERF_TYPE_RAW				= 4,
	PERF_TYPE_BREAKPOINT			= 5,

	PERF_TYPE_MAX,				/* non-ABI */
};

#define PERF_PMU_TYPE_SHIFT		32
#define PERF_HW_EVENT_MASK		0xffffffff

/*
 * Generalized performance event event_id types, used by the
 * attr.event_id parameter of the sys_perf_event_open()
 * syscall:
 */
enum perf_hw_id {
	/*
	 * Common hardware events, generalized by the kernel:
	 */
	PERF_COUNT_HW_CPU_CYCLES		= 0,
	PERF_COUNT_HW_INSTRUCTIONS		= 1,
	PERF_COUNT_HW_CACHE_REFERENCES		= 2,
	PERF_COUNT_HW_CACHE_MISSES		= 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS	= 4,
	PERF_COUNT_HW_BRANCH_MISSES		= 5,
	PERF_COUNT_HW_BUS_CYCLES		= 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND	= 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND	= 8,
	PERF_COUNT_HW_REF_CPU_CYCLES		= 9,

	PERF_COUNT_HW_MAX,			/* non-ABI */
};

enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D			= 0,
	PERF_COUNT_HW_CACHE_L1I			= 1,
	PERF_COUNT_HW_CACHE_LL			= 2,
	PERF_COUNT_HW_CACHE_DTLB		= 3,
	PERF_COUNT_HW_CACHE_ITLB		= 4,
	PERF_COUNT_HW_CACHE_BPU			= 5,
	PERF_COUNT_HW_CACHE_NODE		= 6,

	PERF_COUNT_HW_CACHE_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ		= 0,
	PERF_COUNT_HW_CACHE_OP_WRITE		= 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH		= 2,

	PERF_COUNT_HW_CACHE_OP_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS	= 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS		= 1,

	PERF_COUNT_HW_CACHE_RESULT_MAX,		/* non-ABI */
};

enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK			= 0,
	PERF_COUNT_SW_TASK_CLOCK		= 1,
	PERF_COUNT_SW_PAGE_FAULTS		= 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES		= 3,
	PERF_COUNT_SW_CPU_MIGRATIONS		= 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN		= 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ		= 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS		= 7,
	PERF_COUNT_SW_EMULATION_FAULTS		= 8,
	PERF_COUNT_SW_DUMMY			= 9,
	PERF_COUNT_SW_BPF_OUTPUT		= 10,
	PERF_COUNT_SW_CGROUP_SWITCHES		= 11,

	PERF_COUNT_SW_MAX,			/* non-ABI */
};

/*
 * Bits that can be set in attr.sample_type to request information
 * in the overflow packets.
 */
enum perf_event_sample_format {
	PERF_SAMPLE_IP				= 1U << 0,
	PERF_SAMPLE_TID				= 1U << 1,
	PERF_SAMPLE_TIME			= 1U << 2,
	PERF_SAMPLE_ADDR			= 1U << 3,
	PERF_SAMPLE_READ			= 1U << 4,
	PERF_SAMPLE_CALLCHAIN			= 1U << 5,
	PERF_SAMPLE_ID				= 1U << 6,
	PERF_SAMPLE_CPU				= 1U << 7,
	PERF_SAMPLE_PERIOD			= 1U << 8,
	PERF_SAMPLE_STREAM_ID			= 1U << 9,
	PERF_SAMPLE_RAW				= 1U << 10,
	PERF_SAMPLE_BRANCH_STACK		= 1U << 11,
	PERF_SAMPLE_REGS_USER			= 1U << 12,
	PERF_SAMPLE_STACK_USER			= 1U << 13,
	PERF_SAMPLE_WEIGHT			= 1U << 14,
	PERF_SAMPLE_DATA_SRC			= 1U << 15,
	PERF_SAMPLE_IDENTIFIER			= 1U << 16,
	PERF_SAMPLE_TRANSACTION			= 1U << 17,
	PERF_SAMPLE_REGS_INTR			= 1U << 18,
	PERF_SAMPLE_PHYS_ADDR			= 1U << 19,
	PERF_SAMPLE_AUX				= 1U << 20,
	PERF_SAMPLE_CGROUP			= 1U << 21,
	PERF_SAMPLE_DATA_PAGE_SIZE		= 1U << 22,
	PERF_SAMPLE_CODE_PAGE_SIZE		= 1U << 23,
	PERF_SAMPLE_WEIGHT_STRUCT		= 1U << 24,

	PERF_SAMPLE_MAX = 1U << 25,		/* non-ABI */
};

#define PERF_SAMPLE_WEIGHT_TYPE	(PERF_SAMPLE_WEIGHT | PERF_SAMPLE_WEIGHT_STRUCT)

enum perf_branch_sample_type_shift {
	PERF_SAMPLE_BRANCH_USER_SHIFT		= 0, /* user branches */
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT		= 1, /* kernel branches */
	PERF_SAMPLE_BRANCH_HV_SHIFT		= 2, /* hypervisor branches */

	PERF_SAMPLE_BRANCH_ANY_SHIFT		= 3, /* any branch types */
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT	= 4, /* any call branch */
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT	= 5, /* any return branch */
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT	= 6, /* indirect calls */
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT	= 7, /* transaction aborts */
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT		= 8, /* in transaction */
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT		= 9, /* not in transaction */
	PERF_SAMPLE_BRANCH_COND_SHIFT		= 10, /* conditional branches */

	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT	= 11, /* call/ret stack */
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT	= 12, /* indirect jumps */
	PERF_SAMPLE_BRANCH_CALL_SHIFT		= 13, /* direct call */

	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT	= 14, /* no flags */
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT	= 15, /* no cycles */

	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT	= 16, /* save branch type */

	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT	= 17, /* save low level index of raw branch records */

	PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT	= 18, /* save privilege mode */

	PERF_SAMPLE_BRANCH_MAX_SHIFT		/* non-ABI */
};

enum perf_branch_sample_type {
	PERF_SAMPLE_BRANCH_USER		= 1U << PERF_SAMPLE_BRANCH_USER_SHIFT,
	PERF_SAMPLE_BRANCH_KERNEL	= 1U << PERF_SAMPLE_BRANCH_KERNEL_SHIFT,
	PERF_SAMPLE_BRANCH_HV		= 1U << PERF_SAMPLE_BRANCH_HV_SHIFT,

	PERF_SAMPLE_BRANCH_ANY		= 1U << PERF_SAMPLE_BRANCH_ANY_SHIFT,
	PERF_SAMPLE_BRANCH_ANY_CALL	= 1U << PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT,
	PERF_SAMPLE_BRANCH_ANY_RETURN	= 1U << PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT,
	PERF_SAMPLE_BRANCH_IND_CALL	= 1U << PERF_SAMPLE_BRANCH_IND_CALL_SHIFT,
	PERF_SAMPLE_BRANCH_ABORT_TX	= 1U << PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT,
	PERF_SAMPLE_BRANCH_IN_TX	= 1U << PERF_SAMPLE_BRANCH_IN_TX_SHIFT,
	PERF_SAMPLE_BRANCH_NO_TX	= 1U << PERF_SAMPLE_BRANCH_NO_TX_SHIFT,
	PERF_SAMPLE_BRANCH_COND		= 1U << PERF_SAMPLE_BRANCH_COND_SHIFT,

	PERF_SAMPLE_BRANCH_CALL_STACK	= 1U << PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT,
	PERF_SAMPLE_BRANCH_IND_JUMP	= 1U << PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT,
	PERF_SAMPLE_BRANCH_CALL		= 1U << PERF_SAMPLE_BRANCH_CALL_SHIFT,

	PERF_SAMPLE_BRANCH_NO_FLAGS	= 1U << PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT,
	PERF_SAMPLE_BRANCH_NO_CYCLES	= 1U << PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT,

	PERF_SAMPLE_BRANCH_TYPE_SAVE	=
		1U << PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT,

	PERF_SAMPLE_BRANCH_HW_INDEX	= 1U << PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT,

	PERF_SAMPLE_BRANCH_PRIV_SAVE	= 1U << PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT,

	PERF_SAMPLE_BRANCH_MAX		= 1U << PERF_SAMPLE_BRANCH_MAX_SHIFT,
};

/*
 * Common flow change classification
 */
enum {
	PERF_BR_UNKNOWN		= 0,	/* unknown */
	PERF_BR_COND		= 1,	/* conditional */
	PERF_BR_UNCOND		= 2,	/* unconditional  */
	PERF_BR_IND		= 3,	/* indirect */
	PERF_BR_CALL		= 4,	/* function call */
	PERF_BR_IND_CALL	= 5,	/* indirect function call */
	PERF_BR_RET		= 6,	/* function return */
	PERF_BR_SYSCALL		= 7,	/* syscall */
	PERF_BR_SYSRET		= 8,	/* syscall return */
	PERF_BR_COND_CALL	= 9,	/* conditional function call */
	PERF_BR_COND_RET	= 10,	/* conditional function return */
	PERF_BR_ERET		= 11,	/* exception return */
	PERF_BR_IRQ		= 12,	/* irq */
	PERF_BR_SERROR		= 13,	/* system error */
	PERF_BR_NO_TX		= 14,	/* not in transaction */
	PERF_BR_EXTEND_ABI	= 15,	/* extend ABI */
	PERF_BR_MAX,
};

/*
 * Common branch speculation outcome classification
 */
enum {
	PERF_BR_SPEC_NA			= 0,	/* Not available */
	PERF_BR_SPEC_WRONG_PATH		= 1,	/* Speculative but on wrong path */
	PERF_BR_NON_SPEC_CORRECT_PATH	= 2,	/* Non-speculative but on correct path */
	PERF_BR_SPEC_CORRECT_PATH	= 3,	/* Speculative and on correct path */
	PERF_BR_SPEC_MAX,
};

enum {
	PERF_BR_NEW_FAULT_ALGN		= 0,    /* Alignment fault */
	PERF_BR_NEW_FAULT_DATA		= 1,    /* Data fault */
	PERF_BR_NEW_FAULT_INST		= 2,    /* Inst fault */
	PERF_BR_NEW_ARCH_1		= 3,    /* Architecture specific */
	PERF_BR_NEW_ARCH_2		= 4,    /* Architecture specific */
	PERF_BR_NEW_ARCH_3		= 5,    /* Architecture specific */
	PERF_BR_NEW_ARCH_4		= 6,    /* Architecture specific */
	PERF_BR_NEW_ARCH_5		= 7,    /* Architecture specific */
	PERF_BR_NEW_MAX,
};

enum {
	PERF_BR_PRIV_UNKNOWN	= 0,
	PERF_BR_PRIV_USER	= 1,
	PERF_BR_PRIV_KERNEL	= 2,
	PERF_BR_PRIV_HV		= 3,
};

#define PERF_BR_ARM64_FIQ		PERF_BR_NEW_ARCH_1
#define PERF_BR_ARM64_DEBUG_HALT	PERF_BR_NEW_ARCH_2
#define PERF_BR_ARM64_DEBUG_EXIT	PERF_BR_NEW_ARCH_3
#define PERF_BR_ARM64_DEBUG_INST	PERF_BR_NEW_ARCH_4
#define PERF_BR_ARM64_DEBUG_DATA	PERF_BR_NEW_ARCH_5

#define PERF_SAMPLE_BRANCH_PLM_ALL \
	(PERF_SAMPLE_BRANCH_USER|\
	 PERF_SAMPLE_BRANCH_KERNEL|\
	 PERF_SAMPLE_BRANCH_HV)

/*
 * Values to determine ABI of the registers dump.
 */
enum perf_sample_regs_abi {
	PERF_SAMPLE_REGS_ABI_NONE	= 0,
	PERF_SAMPLE_REGS_ABI_32		= 1,
	PERF_SAMPLE_REGS_ABI_64		= 2,
};

/*
 * Values for the memory transaction event qualifier, mostly for
 * abort events. Multiple bits can be set.
 */
enum {
	PERF_TXN_ELISION        = (1 << 0), /* From elision */
	PERF_TXN_TRANSACTION    = (1 << 1), /* From transaction */
	PERF_TXN_SYNC           = (1 << 2), /* Instruction is related */
	PERF_TXN_ASYNC          = (1 << 3), /* Instruction not related */
	PERF_TXN_RETRY          = (1 << 4), /* Retry possible */
	PERF_TXN_CONFLICT       = (1 << 5), /* Conflict abort */
	PERF_TXN_CAPACITY_WRITE = (1 << 6), /* Capacity write abort */
	PERF_TXN_CAPACITY_READ  = (1 << 7), /* Capacity read abort */

	PERF_TXN_MAX	        = (1 << 8), /* non-ABI */

	/* bits 32..63 are reserved for the abort code */

	PERF_TXN_ABORT_MASK  = (0xffffffffULL << 32),
	PERF_TXN_ABORT_SHIFT = 32,
};

enum perf_event_read_format {
	PERF_FORMAT_TOTAL_TIME_ENABLED		= 1U << 0,
	PERF_FORMAT_TOTAL_TIME_RUNNING		= 1U << 1,
	PERF_FORMAT_ID				= 1U << 2,
	PERF_FORMAT_GROUP			= 1U << 3,
	PERF_FORMAT_LOST			= 1U << 4,

	PERF_FORMAT_MAX = 1U << 5,		/* non-ABI */
};

#define PERF_ATTR_SIZE_VER0	64	/* sizeof first published struct */
#define PERF_ATTR_SIZE_VER1	72	/* add: config2 */
#define PERF_ATTR_SIZE_VER2	80	/* add: branch_sample_type */
#define PERF_ATTR_SIZE_VER3	96	/* add: sample_regs_user */
					/* add: sample_stack_user */
#define PERF_ATTR_SIZE_VER4	104	/* add: sample_regs_intr */
#define PERF_ATTR_SIZE_VER5	112	/* add: aux_watermark */
#define PERF_ATTR_SIZE_VER6	120	/* add: aux_sample_size */
#define PERF_ATTR_SIZE_VER7	128	/* add: sig_data */
#define PERF_ATTR_SIZE_VER8	136	/* add: config3 */

struct perf_event_attr {

	__u32			type;
	__u32			size;
	__u64			config;

	union {
		__u64		sample_period;
		__u64		sample_freq;
	};

	__u64			sample_type;
	__u64			read_format;

		__u64			disabled       :  1, /* off by default        */
				inherit	       :  1, /* children inherit it   */
				pinned	       :  1, /* must always be on PMU */
				exclusive      :  1, /* only group on PMU     */
				exclude_user   :  1, /* don't count user      */
				exclude_kernel :  1, /* ditto kernel          */
				exclude_hv     :  1, /* ditto hypervisor      */
				exclude_idle   :  1, /* don't count when idle */
				mmap           :  1, /* include mmap data     */
				comm	       :  1, /* include comm data     */
				freq           :  1, /* use freq, not period  */
				inherit_stat   :  1, /* per task counts       */
				enable_on_exec :  1, /* next exec enables     */
				task           :  1, /* trace fork/exit       */
				watermark      :  1, /* wakeup_watermark      */
				
				precise_ip     :  2, /* skid constraint       */
				mmap_data      :  1, /* non-exec mmap data    */
				sample_id_all  :  1, /* sample_type all events */

				exclude_host   :  1, /* don't count in host   */
				exclude_guest  :  1, /* don't count in guest  */

				exclude_callchain_kernel : 1, /* exclude kernel callchains */
				exclude_callchain_user   : 1, /* exclude user callchains */
				mmap2          :  1, /* include mmap with inode data     */
				comm_exec      :  1, /* flag comm events that are due to an exec */
				use_clockid    :  1, /* use @clockid for time fields */
				context_switch :  1, /* context switch data */
				write_backward :  1, /* Write ring buffer from end to beginning */
				namespaces     :  1, /* include namespaces data */
				ksymbol        :  1, /* include ksymbol events */
				bpf_event      :  1, /* include bpf events */
				aux_output     :  1, /* generate AUX records instead of events */
				cgroup         :  1, /* include cgroup events */
				text_poke      :  1, /* include text poke events */
				build_id       :  1, /* use build id in mmap2 events */
				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
				remove_on_exec :  1, /* event is removed from task on exec */
				sigtrap        :  1, /* send synchronous SIGTRAP on event */
				__reserved_1   : 26;

	union {
		__u32		wakeup_events;	  /* wakeup every n events */
		__u32		wakeup_watermark; /* bytes before wakeup   */
	};

	__u32			bp_type;
	union {
		__u64		bp_addr;
		__u64		kprobe_func; /* for perf_kprobe */
		__u64		uprobe_path; /* for perf_uprobe */
		__u64		config1; /* extension of config */
	};
	union {
		__u64		bp_len;
		__u64		kprobe_addr; /* when kprobe_func == NULL */
		__u64		probe_offset; /* for perf_[k,u]probe */
		__u64		config2; /* extension of config1 */
	};
	__u64	branch_sample_type; /* enum perf_branch_sample_type */

	__u64	sample_regs_user;

	__u32	sample_stack_user;

	__s32	clockid;

	__u64	sample_regs_intr;

	__u32	aux_watermark;
	__u16	sample_max_stack;
	__u16	__reserved_2;
	__u32	aux_sample_size;
	__u32	__reserved_3;

	__u64	sig_data;

	__u64	config3; /* extension of config2 */
};

struct perf_event_query_bpf {
	__u32	ids_len;
	__u32	prog_cnt;
	__u32	ids[];
};

/*
 * Ioctls that can be done on a perf event fd:
 */
#define PERF_EVENT_IOC_ENABLE			_IO ('$', 0)
#define PERF_EVENT_IOC_DISABLE			_IO ('$', 1)
#define PERF_EVENT_IOC_REFRESH			_IO ('$', 2)
#define PERF_EVENT_IOC_RESET			_IO ('$', 3)
#define PERF_EVENT_IOC_PERIOD			_IOW('$', 4, __u64)
#define PERF_EVENT_IOC_SET_OUTPUT		_IO ('$', 5)
#define PERF_EVENT_IOC_SET_FILTER		_IOW('$', 6, char *)
#define PERF_EVENT_IOC_ID			_IOR('$', 7, __u64 *)
#define PERF_EVENT_IOC_SET_BPF			_IOW('$', 8, __u32)
#define PERF_EVENT_IOC_PAUSE_OUTPUT		_IOW('$', 9, __u32)
#define PERF_EVENT_IOC_QUERY_BPF		_IOWR('$', 10, struct perf_event_query_bpf *)
#define PERF_EVENT_IOC_MODIFY_ATTRIBUTES	_IOW('$', 11, struct perf_event_attr *)

enum perf_event_ioc_flags {
	PERF_IOC_FLAG_GROUP		= 1U << 0,
};

/*
 * Structure of the page that can be mapped via mmap
 */
struct perf_event_mmap_page {
	__u32	version;		/* version number of this structure */
	__u32	compat_version;		/* lowest version this is compat with */

	__u32	lock;			/* seqlock for synchronization */
	__u32	index;			/* hardware event identifier */
	__s64	offset;			/* add to hardware event value */
	__u64	time_enabled;		/* time event active */
	__u64	time_running;		/* time event on cpu */
	union {
		__u64	capabilities;
		struct {
			__u64	cap_bit0		: 1, /* Always 0, deprecated, see commit 860f085b74e9 */
				cap_bit0_is_deprecated	: 1, /* Always 1, signals that bit 0 is zero */

				cap_user_rdpmc		: 1, /* The RDPMC instruction can be used to read counts */
				cap_user_time		: 1, /* The time_{shift,mult,offset} fields are used */
				cap_user_time_zero	: 1, /* The time_zero field is used */
				cap_user_time_short	: 1, /* the time_{cycle,mask} fields are used */
				cap_____res		: 58;
		};
	};

	__u16	pmc_width;
	__u16	time_shift;
	__u32	time_mult;
	__u64	time_offset;
	__u64	time_zero;
	__u32	size;			/* Header size up to __reserved[] fields. */
	__u32	__reserved_1;
	__u64	time_cycles;
	__u64	time_mask;
	__u8	__reserved[116*8];	/* align to 1k. */
	__u64   data_head;		/* head in the data section */
	__u64	data_tail;		/* user-space written tail */
	__u64	data_offset;		/* where the buffer starts */
	__u64	data_size;		/* data buffer size */
	__u64	aux_head;
	__u64	aux_tail;
	__u64	aux_offset;
	__u64	aux_size;
};

#define PERF_RECORD_MISC_CPUMODE_MASK		(7 << 0)
#define PERF_RECORD_MISC_CPUMODE_UNKNOWN	(0 << 0)
#define PERF_RECORD_MISC_KERNEL			(1 << 0)
#define PERF_RECORD_MISC_USER			(2 << 0)
#define PERF_RECORD_MISC_HYPERVISOR		(3 << 0)
#define PERF_RECORD_MISC_GUEST_KERNEL		(4 << 0)
#define PERF_RECORD_MISC_GUEST_USER		(5 << 0)

/*
 * Indicates that /proc/PID/maps parsing are truncated by time out.
 */
#define PERF_RECORD_MISC_PROC_MAP_PARSE_TIMEOUT	(1 << 12)

#define PERF_RECORD_MISC_MMAP_DATA		(1 << 13)
#define PERF_RECORD_MISC_COMM_EXEC		(1 << 13)
#define PERF_RECORD_MISC_FORK_EXEC		(1 << 13)
#define PERF_RECORD_MISC_SWITCH_OUT		(1 << 13)

#define PERF_RECORD_MISC_EXACT_IP		(1 << 14)
#define PERF_RECORD_MISC_SWITCH_OUT_PREEMPT	(1 << 14)
#define PERF_RECORD_MISC_MMAP_BUILD_ID		(1 << 14)
/*
 * Reserve the last bit to indicate some extended misc field
 */
#define PERF_RECORD_MISC_EXT_RESERVED		(1 << 15)

struct perf_event_header {
	__u32	type;
	__u16	misc;
	__u16	size;
};

struct perf_ns_link_info {
	__u64	dev;
	__u64	ino;
};

enum {
	NET_NS_INDEX		= 0,
	UTS_NS_INDEX		= 1,
	IPC_NS_INDEX		= 2,
	PID_NS_INDEX		= 3,
	USER_NS_INDEX		= 4,
	MNT_NS_INDEX		= 5,
	CGROUP_NS_INDEX		= 6,

	NR_NAMESPACES,		/* number of available namespaces */
};

enum perf_event_type {
	PERF_RECORD_MMAP					= 1,
	PERF_RECORD_LOST					= 2,
	PERF_RECORD_COMM					= 3,
	PERF_RECORD_EXIT					= 4,
	PERF_RECORD_THROTTLE				= 5,
	PERF_RECORD_UNTHROTTLE				= 6,
	PERF_RECORD_FORK					= 7,
	PERF_RECORD_READ					= 8,
	PERF_RECORD_SAMPLE					= 9,
	PERF_RECORD_MMAP2					= 10,
	PERF_RECORD_AUX						= 11,
	PERF_RECORD_ITRACE_START			= 12,
	PERF_RECORD_LOST_SAMPLES			= 13,
	PERF_RECORD_SWITCH					= 14,
	PERF_RECORD_SWITCH_CPU_WIDE			= 15,
	PERF_RECORD_NAMESPACES				= 16,
	PERF_RECORD_KSYMBOL					= 17,
	PERF_RECORD_BPF_EVENT				= 18,
	PERF_RECORD_CGROUP					= 19,
	PERF_RECORD_TEXT_POKE				= 20,
	PERF_RECORD_AUX_OUTPUT_HW_ID		= 21,
	PERF_RECORD_MAX,			/* non-ABI */
};

enum perf_record_ksymbol_type {
	PERF_RECORD_KSYMBOL_TYPE_UNKNOWN	= 0,
	PERF_RECORD_KSYMBOL_TYPE_BPF		= 1,
	/*
	 * Out of line code such as kprobe-replaced instructions or optimized
	 * kprobes or ftrace trampolines.
	 */
	PERF_RECORD_KSYMBOL_TYPE_OOL		= 2,
	PERF_RECORD_KSYMBOL_TYPE_MAX		/* non-ABI */
};

#define PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER	(1 << 0)

enum perf_bpf_event_type {
	PERF_BPF_EVENT_UNKNOWN		= 0,
	PERF_BPF_EVENT_PROG_LOAD	= 1,
	PERF_BPF_EVENT_PROG_UNLOAD	= 2,
	PERF_BPF_EVENT_MAX,		/* non-ABI */
};

#define PERF_MAX_STACK_DEPTH		127
#define PERF_MAX_CONTEXTS_PER_STACK	  8

enum perf_callchain_context {
	PERF_CONTEXT_HV			= (__u64)-32,
	PERF_CONTEXT_KERNEL		= (__u64)-128,
	PERF_CONTEXT_USER		= (__u64)-512,

	PERF_CONTEXT_GUEST		= (__u64)-2048,
	PERF_CONTEXT_GUEST_KERNEL	= (__u64)-2176,
	PERF_CONTEXT_GUEST_USER		= (__u64)-2560,

	PERF_CONTEXT_MAX		= (__u64)-4095,
};

/**
 * PERF_RECORD_AUX::flags bits
 */
#define PERF_AUX_FLAG_TRUNCATED			0x01	/* record was truncated to fit */
#define PERF_AUX_FLAG_OVERWRITE			0x02	/* snapshot from overwrite mode */
#define PERF_AUX_FLAG_PARTIAL			0x04	/* record contains gaps */
#define PERF_AUX_FLAG_COLLISION			0x08	/* sample collided with another */
#define PERF_AUX_FLAG_PMU_FORMAT_TYPE_MASK	0xff00	/* PMU specific trace format type */

/* CoreSight PMU AUX buffer formats */
#define PERF_AUX_FLAG_CORESIGHT_FORMAT_CORESIGHT	0x0000 /* Default for backward compatibility */
#define PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW		0x0100 /* Raw format of the source */

#define PERF_FLAG_FD_NO_GROUP		(1UL << 0)
#define PERF_FLAG_FD_OUTPUT		(1UL << 1)
#define PERF_FLAG_PID_CGROUP		(1UL << 2) /* pid=cgroup id, per-cpu mode only */
#define PERF_FLAG_FD_CLOEXEC		(1UL << 3) /* O_CLOEXEC */

#if defined(__LITTLE_ENDIAN_BITFIELD)
union perf_mem_data_src {
	__u64 val;
	struct {
		__u64   mem_op:5,	/* type of opcode */
			mem_lvl:14,	/* memory hierarchy level */
			mem_snoop:5,	/* snoop mode */
			mem_lock:2,	/* lock instr */
			mem_dtlb:7,	/* tlb access */
			mem_lvl_num:4,	/* memory hierarchy level number */
			mem_remote:1,   /* remote */
			mem_snoopx:2,	/* snoop mode, ext */
			mem_blk:3,	/* access blocked */
			mem_hops:3,	/* hop level */
			mem_rsvd:18;
	};
};
#elif defined(__BIG_ENDIAN_BITFIELD)
union perf_mem_data_src {
	__u64 val;
	struct {
		__u64	mem_rsvd:18,
			mem_hops:3,	/* hop level */
			mem_blk:3,	/* access blocked */
			mem_snoopx:2,	/* snoop mode, ext */
			mem_remote:1,   /* remote */
			mem_lvl_num:4,	/* memory hierarchy level number */
			mem_dtlb:7,	/* tlb access */
			mem_lock:2,	/* lock instr */
			mem_snoop:5,	/* snoop mode */
			mem_lvl:14,	/* memory hierarchy level */
			mem_op:5;	/* type of opcode */
	};
};
#else
#error "Unknown endianness"
#endif

/* type of opcode (load/store/prefetch,code) */
#define PERF_MEM_OP_NA		0x01 /* not available */
#define PERF_MEM_OP_LOAD	0x02 /* load instruction */
#define PERF_MEM_OP_STORE	0x04 /* store instruction */
#define PERF_MEM_OP_PFETCH	0x08 /* prefetch */
#define PERF_MEM_OP_EXEC	0x10 /* code (execution) */
#define PERF_MEM_OP_SHIFT	0

/*
 * PERF_MEM_LVL_* namespace being depricated to some extent in the
 * favour of newer composite PERF_MEM_{LVLNUM_,REMOTE_,SNOOPX_} fields.
 * Supporting this namespace inorder to not break defined ABIs.
 *
 * memory hierarchy (memory level, hit or miss)
 */
#define PERF_MEM_LVL_NA		0x01  /* not available */
#define PERF_MEM_LVL_HIT	0x02  /* hit level */
#define PERF_MEM_LVL_MISS	0x04  /* miss level  */
#define PERF_MEM_LVL_L1		0x08  /* L1 */
#define PERF_MEM_LVL_LFB	0x10  /* Line Fill Buffer */
#define PERF_MEM_LVL_L2		0x20  /* L2 */
#define PERF_MEM_LVL_L3		0x40  /* L3 */
#define PERF_MEM_LVL_LOC_RAM	0x80  /* Local DRAM */
#define PERF_MEM_LVL_REM_RAM1	0x100 /* Remote DRAM (1 hop) */
#define PERF_MEM_LVL_REM_RAM2	0x200 /* Remote DRAM (2 hops) */
#define PERF_MEM_LVL_REM_CCE1	0x400 /* Remote Cache (1 hop) */
#define PERF_MEM_LVL_REM_CCE2	0x800 /* Remote Cache (2 hops) */
#define PERF_MEM_LVL_IO		0x1000 /* I/O memory */
#define PERF_MEM_LVL_UNC	0x2000 /* Uncached memory */
#define PERF_MEM_LVL_SHIFT	5
