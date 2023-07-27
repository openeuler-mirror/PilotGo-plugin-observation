#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

enum
{
	false = 0,
	true = 1,
};

typedef long int __kernel_long_t;

typedef long unsigned int __kernel_ulong_t;

typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef __kernel_ulong_t __kernel_size_t;

typedef __kernel_long_t __kernel_ssize_t;

typedef long long int __kernel_loff_t;

typedef long long int __kernel_time64_t;

typedef __kernel_long_t __kernel_clock_t;

typedef int __kernel_timer_t;

typedef int __kernel_clockid_t;

typedef unsigned int __poll_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef short unsigned int umode_t;

typedef __kernel_pid_t pid_t;

typedef __kernel_clockid_t clockid_t;

typedef _Bool bool;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_size_t size_t;

typedef __kernel_ssize_t ssize_t;

typedef s32 int32_t;

typedef u32 uint32_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

typedef unsigned int fmode_t;

typedef u64 phys_addr_t;

typedef struct
{
	int counter;
} atomic_t;

typedef struct
{
	s64 counter;
} atomic64_t;

struct list_head
{
	struct list_head *next;
	struct list_head *prev;
};

struct hlist_node;

struct hlist_head
{
	struct hlist_node *first;
};

struct hlist_node
{
	struct hlist_node *next;
	struct hlist_node **pprev;
};

struct callback_head
{
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct kernel_symbol
{
	int value_offset;
	int name_offset;
	int namespace_offset;
};

struct lockdep_subclass_key
{
	char __one_byte;
};

struct lock_class_key
{
	union
	{
		struct hlist_node hash_entry;
		struct lockdep_subclass_key subkeys[8];
	};
};

struct fs_context;

struct fs_parameter_spec;

struct dentry;

struct super_block;

struct module;

struct file_system_type
{
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry *(*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct qspinlock
{
	union
	{
		atomic_t val;
		struct
		{
			u8 locked;
			u8 pending;
		};
		struct
		{
			u16 locked_pending;
			u16 tail;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;

struct qrwlock
{
	union
	{
		atomic_t cnts;
		struct
		{
			u8 wlocked;
			u8 __lstate[3];
		};
	};
	arch_spinlock_t wait_lock;
};

typedef struct qrwlock arch_rwlock_t;

struct lock_trace;

struct lock_class
{
	struct hlist_node hash_entry;
	struct list_head lock_entry;
	struct list_head locks_after;
	struct list_head locks_before;
	const struct lockdep_subclass_key *key;
	unsigned int subclass;
	unsigned int dep_gen_id;
	long unsigned int usage_mask;
	const struct lock_trace *usage_traces[10];
	int name_version;
	const char *name;
	u8 wait_type_inner;
	u8 wait_type_outer;
	u8 lock_type;
};

struct lock_trace
{
	struct hlist_node hash_entry;
	u32 hash;
	u32 nr_entries;
	long unsigned int entries[0];
};

struct lockdep_map
{
	struct lock_class_key *key;
	struct lock_class *class_cache[2];
	const char *name;
	u8 wait_type_outer;
	u8 wait_type_inner;
	u8 lock_type;
};

struct raw_spinlock
{
	arch_spinlock_t raw_lock;
	unsigned int magic;
	unsigned int owner_cpu;
	void *owner;
	struct lockdep_map dep_map;
};

typedef struct raw_spinlock raw_spinlock_t;

struct ratelimit_state
{
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	long unsigned int begin;
	long unsigned int flags;
};

typedef void *fl_owner_t;

struct file;

struct kiocb;

struct iov_iter;

struct io_comp_batch;

struct dir_context;

struct poll_table_struct;

struct vm_area_struct;

struct inode;

struct file_lock;

struct page;

struct pipe_inode_info;

struct seq_file;

struct io_uring_cmd;

struct file_operations
{
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file *, struct dir_context *);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	ssize_t (*sendpage)(struct file *, struct page *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long int, struct file_lock **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct static_call_site
{
	s32 addr;
	s32 key;
};

struct static_call_mod
{
	struct static_call_mod *next;
	struct module *mod;
	struct static_call_site *sites;
};

struct static_call_key
{
	void *func;
	union
	{
		long unsigned int type;
		struct static_call_mod *mods;
		struct static_call_site *sites;
	};
};

struct thread_info
{
	long unsigned int flags;
	long unsigned int syscall_work;
	u32 status;
	u32 cpu;
};

struct refcount_struct
{
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct llist_node
{
	struct llist_node *next;
};

struct __call_single_node
{
	struct llist_node llist;
	union
	{
		unsigned int u_flags;
		atomic_t a_flags;
	};
	u16 src;
	u16 dst;
};

struct load_weight
{
	long unsigned int weight;
	u32 inv_weight;
};

struct rb_node
{
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct util_est
{
	unsigned int enqueued;
	unsigned int ewma;
};

struct sched_avg
{
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	struct util_est util_est;
};

struct cfs_rq;

struct sched_entity
{
	struct load_weight load;
	struct rb_node run_node;
	struct list_head group_node;
	unsigned int on_rq;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 vruntime;
	u64 prev_sum_exec_runtime;
	u64 nr_migrations;
	int depth;
	struct sched_entity *parent;
	struct cfs_rq *cfs_rq;
	struct cfs_rq *my_q;
	long unsigned int runnable_weight;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	struct sched_avg avg;
};

struct sched_rt_entity
{
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
};

typedef s64 ktime_t;

struct timerqueue_node
{
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart
{
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

struct hrtimer_clock_base;

struct hrtimer
{
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};

struct sched_dl_entity
{
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled : 1;
	unsigned int dl_yielded : 1;
	unsigned int dl_non_contending : 1;
	unsigned int dl_overrun : 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct sched_dl_entity *pi_se;
};

struct sched_statistics
{
	u64 wait_start;
	u64 wait_max;
	u64 wait_count;
	u64 wait_sum;
	u64 iowait_count;
	u64 iowait_sum;
	u64 sleep_start;
	u64 sleep_max;
	s64 sum_sleep_runtime;
	u64 block_start;
	u64 block_max;
	s64 sum_block_runtime;
	u64 exec_max;
	u64 slice_max;
	u64 nr_migrations_cold;
	u64 nr_failed_migrations_affine;
	u64 nr_failed_migrations_running;
	u64 nr_failed_migrations_hot;
	u64 nr_forced_migrations;
	u64 nr_wakeups;
	u64 nr_wakeups_sync;
	u64 nr_wakeups_migrate;
	u64 nr_wakeups_local;
	u64 nr_wakeups_remote;
	u64 nr_wakeups_affine;
	u64 nr_wakeups_affine_attempts;
	u64 nr_wakeups_passive;
	u64 nr_wakeups_idle;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
};

struct cpumask
{
	long unsigned int bits[2];
};

typedef struct cpumask cpumask_t;

union rcu_special
{
	struct
	{
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

struct sched_info
{
	long unsigned int pcount;
	long long unsigned int run_delay;
	long long unsigned int last_arrival;
	long long unsigned int last_queued;
};

struct plist_node
{
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

struct task_rss_stat
{
	int events;
	int count[4];
};

enum timespec_type
{
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

struct __kernel_timespec;

struct old_timespec32;

struct pollfd;

struct restart_block
{
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union
	{
		struct
		{
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct
		{
			clockid_t clockid;
			enum timespec_type type;
			union
			{
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct
		{
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

struct prev_cputime
{
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct rb_root
{
	struct rb_node *rb_node;
};

struct rb_root_cached
{
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct timerqueue_head
{
	struct rb_root_cached rb_root;
};

struct posix_cputimer_base
{
	u64 nextevt;
	struct timerqueue_head tqhead;
};

struct posix_cputimers
{
	struct posix_cputimer_base bases[3];
	unsigned int timers_active;
	unsigned int expiry_active;
};

struct posix_cputimers_work
{
	struct callback_head work;
	unsigned int scheduled;
};

struct sem_undo_list;

struct sysv_sem
{
	struct sem_undo_list *undo_list;
};

struct sysv_shm
{
	struct list_head shm_clist;
};

typedef struct
{
	long unsigned int sig[1];
} sigset_t;

struct sigpending
{
	struct list_head list;
	sigset_t signal;
};

typedef struct
{
	uid_t val;
} kuid_t;

struct seccomp_filter;

struct seccomp
{
	int mode;
	atomic_t filter_count;
	struct seccomp_filter *filter;
};

struct syscall_user_dispatch
{
	char *selector;
	long unsigned int offset;
	long unsigned int len;
	bool on_dispatch;
};

struct spinlock
{
	union
	{
		struct raw_spinlock rlock;
		struct
		{
			u8 __padding[24];
			struct lockdep_map dep_map;
		};
	};
};

typedef struct spinlock spinlock_t;

struct wake_q_node
{
	struct wake_q_node *next;
};

struct irqtrace_events
{
	unsigned int irq_events;
	long unsigned int hardirq_enable_ip;
	long unsigned int hardirq_disable_ip;
	unsigned int hardirq_enable_event;
	unsigned int hardirq_disable_event;
	long unsigned int softirq_disable_ip;
	long unsigned int softirq_enable_ip;
	unsigned int softirq_disable_event;
	unsigned int softirq_enable_event;
};

struct held_lock
{
	u64 prev_chain_key;
	long unsigned int acquire_ip;
	struct lockdep_map *instance;
	struct lockdep_map *nest_lock;
	unsigned int class_idx : 13;
	unsigned int irq_context : 2;
	unsigned int trylock : 1;
	unsigned int read : 2;
	unsigned int check : 1;
	unsigned int hardirqs_off : 1;
	unsigned int references : 12;
	unsigned int pin_count;
};

struct task_io_accounting
{
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};

typedef struct
{
	long unsigned int bits[1];
} nodemask_t;

struct seqcount
{
	unsigned int sequence;
	struct lockdep_map dep_map;
};

typedef struct seqcount seqcount_t;

struct seqcount_spinlock
{
	seqcount_t seqcount;
	spinlock_t *lock;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

typedef atomic64_t atomic_long_t;

struct optimistic_spin_queue
{
	atomic_t tail;
};

struct mutex
{
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
	void *magic;
	struct lockdep_map dep_map;
};

struct arch_tlbflush_unmap_batch
{
	struct cpumask cpumask;
};

struct tlbflush_unmap_batch
{
	struct arch_tlbflush_unmap_batch arch;
	bool flush_required;
	bool writable;
};

struct page_frag
{
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct kmap_ctrl
{
};

struct timer_list
{
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
	struct lockdep_map lockdep_map;
};

struct llist_head
{
	struct llist_node *first;
};

struct desc_struct
{
	u16 limit0;
	u16 base0;
	u16 base1 : 8;
	u16 type : 4;
	u16 s : 1;
	u16 dpl : 2;
	u16 p : 1;
	u16 limit1 : 4;
	u16 avl : 1;
	u16 l : 1;
	u16 d : 1;
	u16 g : 1;
	u16 base2 : 8;
};

struct fpu_state_perm
{
	u64 __state_perm;
	unsigned int __state_size;
	unsigned int __user_state_size;
};

struct fregs_state
{
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u32 status;
};

struct fxregs_state
{
	u16 cwd;
	u16 swd;
	u16 twd;
	u16 fop;
	union
	{
		struct
		{
			u64 rip;
			u64 rdp;
		};
		struct
		{
			u32 fip;
			u32 fcs;
			u32 foo;
			u32 fos;
		};
	};
	u32 mxcsr;
	u32 mxcsr_mask;
	u32 st_space[32];
	u32 xmm_space[64];
	u32 padding[12];
	union
	{
		u32 padding1[12];
		u32 sw_reserved[12];
	};
};

struct math_emu_info;

struct swregs_state
{
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u8 ftop;
	u8 changed;
	u8 lookahead;
	u8 no_update;
	u8 rm;
	u8 alimit;
	struct math_emu_info *info;
	u32 entry_eip;
};

struct xstate_header
{
	u64 xfeatures;
	u64 xcomp_bv;
	u64 reserved[6];
};

struct xregs_state
{
	struct fxregs_state i387;
	struct xstate_header header;
	u8 extended_state_area[0];
};

union fpregs_state
{
	struct fregs_state fsave;
	struct fxregs_state fxsave;
	struct swregs_state soft;
	struct xregs_state xsave;
	u8 __padding[4096];
};

struct fpstate
{
	unsigned int size;
	unsigned int user_size;
	u64 xfeatures;
	u64 user_xfeatures;
	u64 xfd;
	unsigned int is_valloc : 1;
	unsigned int is_guest : 1;
	unsigned int is_confidential : 1;
	unsigned int in_use : 1;
	long : 64;
	long : 64;
	long : 64;
	union fpregs_state regs;
};

struct fpu
{
	unsigned int last_cpu;
	long unsigned int avx512_timestamp;
	struct fpstate *fpstate;
	struct fpstate *__task_fpstate;
	struct fpu_state_perm perm;
	struct fpu_state_perm guest_perm;
	struct fpstate __fpstate;
};

struct perf_event;

struct io_bitmap;

struct thread_struct
{
	struct desc_struct tls_array[3];
	long unsigned int sp;
	short unsigned int es;
	short unsigned int ds;
	short unsigned int fsindex;
	short unsigned int gsindex;
	long unsigned int fsbase;
	long unsigned int gsbase;
	struct perf_event *ptrace_bps[4];
	long unsigned int virtual_dr6;
	long unsigned int ptrace_dr7;
	long unsigned int cr2;
	long unsigned int trap_nr;
	long unsigned int error_code;
	struct io_bitmap *io_bitmap;
	long unsigned int iopl_emul;
	unsigned int iopl_warn : 1;
	unsigned int sig_on_uaccess_err : 1;
	u32 pkru;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	struct fpu fpu;
};

struct sched_class;

struct task_group;

struct rcu_node;

struct mm_struct;

struct pid;

struct completion;

struct cred;

struct key;

struct nameidata;

struct fs_struct;

struct files_struct;

struct io_uring_task;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct audit_context;

struct rt_mutex_waiter;

struct mutex_waiter;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct backing_dev_info;

struct io_context;

struct capture_control;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct css_set;

struct robust_list_head;

struct futex_pi_state;

struct perf_event_context;

struct mempolicy;

struct numa_group;

struct rseq;

struct task_delay_info;

struct ftrace_ret_stack;

struct mem_cgroup;

struct request_queue;

struct uprobe_task;

struct vm_struct;

struct bpf_local_storage;

struct bpf_run_ctx;

struct task_struct
{
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct task_group *sched_task_group;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	struct sched_statistics stats;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork : 1;
	unsigned int sched_contributes_to_load : 1;
	unsigned int sched_migrated : 1;
	long : 29;
	unsigned int sched_remote_wakeup : 1;
	unsigned int in_execve : 1;
	unsigned int in_iowait : 1;
	unsigned int restore_sigmask : 1;
	unsigned int in_user_fault : 1;
	unsigned int brk_randomized : 1;
	unsigned int no_cgroup_migration : 1;
	unsigned int frozen : 1;
	unsigned int use_memdelay : 1;
	unsigned int in_eventfd : 1;
	unsigned int reported_split_lock : 1;
	unsigned int in_thrashing : 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	long unsigned int last_switch_count;
	long unsigned int last_switch_time;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	struct mutex_waiter *blocked_on;
	int non_block_count;
	struct irqtrace_events irqtrace;
	unsigned int hardirq_threaded;
	u64 hardirq_chain_key;
	int softirqs_enabled;
	int softirq_context;
	int irq_config;
	u64 curr_chain_key;
	int lockdep_depth;
	unsigned int lockdep_recursion;
	struct held_lock held_locks[48];
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set *cgroups;
	struct list_head cg_list;
	struct robust_list_head *robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union
	{
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	struct task_delay_info *delays;
	int make_it_fail;
	unsigned int fail_nth;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	struct kmap_ctrl kmap_ctrl;
	long unsigned int task_state_change;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct *stack_vm_area;
	refcount_t stack_refcount;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv : 1;
	__u64 mce_whole_page : 1;
	__u64 __mce_reserved : 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	long : 64;
	long : 64;
	struct thread_struct thread;
};

struct jump_entry
{
	s32 code;
	s32 target;
	long int key;
};

struct static_key_mod;

struct static_key
{
	atomic_t enabled;
	union
	{
		long unsigned int type;
		struct jump_entry *entries;
		struct static_key_mod *next;
	};
};

struct orc_entry
{
	s16 sp_offset;
	s16 bp_offset;
	unsigned int sp_reg : 4;
	unsigned int bp_reg : 4;
	unsigned int type : 2;
	unsigned int end : 1;
} __attribute__((packed));

struct bug_entry
{
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};

typedef __s64 time64_t;

struct __kernel_timespec
{
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

struct timespec64
{
	time64_t tv_sec;
	long int tv_nsec;
};

typedef s32 old_time32_t;

struct old_timespec32
{
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct pt_regs
{
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

struct math_emu_info
{
	long int ___orig_eip;
	struct pt_regs *regs;
};

typedef long unsigned int pgdval_t;

typedef long unsigned int pgprotval_t;

struct pgprot
{
	pgprotval_t pgprot;
};

typedef struct pgprot pgprot_t;

typedef struct
{
	pgdval_t pgd;
} pgd_t;

typedef struct page *pgtable_t;

struct address_space;

struct page_pool;

struct dev_pagemap;

struct page
{
	long unsigned int flags;
	union
	{
		struct
		{
			union
			{
				struct list_head lru;
				struct
				{
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct
		{
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union
			{
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct
		{
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct
		{
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct
		{
			long unsigned int _pt_pad_1;
			pgtable_t pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union
			{
				struct mm_struct *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t *ptl;
		};
		struct
		{
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union
	{
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct tracepoint_func
{
	void *func;
	void *data;
	int prio;
};

struct tracepoint
{
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

typedef const int tracepoint_ptr_t;

struct bpf_raw_event_map
{
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long : 64;
};

enum xfeature
{
	XFEATURE_FP = 0,
	XFEATURE_SSE = 1,
	XFEATURE_YMM = 2,
	XFEATURE_BNDREGS = 3,
	XFEATURE_BNDCSR = 4,
	XFEATURE_OPMASK = 5,
	XFEATURE_ZMM_Hi256 = 6,
	XFEATURE_Hi16_ZMM = 7,
	XFEATURE_PT_UNIMPLEMENTED_SO_FAR = 8,
	XFEATURE_PKRU = 9,
	XFEATURE_PASID = 10,
	XFEATURE_RSRVD_COMP_11 = 11,
	XFEATURE_RSRVD_COMP_12 = 12,
	XFEATURE_RSRVD_COMP_13 = 13,
	XFEATURE_RSRVD_COMP_14 = 14,
	XFEATURE_LBR = 15,
	XFEATURE_RSRVD_COMP_16 = 16,
	XFEATURE_XTILE_CFG = 17,
	XFEATURE_XTILE_DATA = 18,
	XFEATURE_MAX = 19,
};

struct fpu_state_config
{
	unsigned int max_size;
	unsigned int default_size;
	u64 max_features;
	u64 default_features;
	u64 legacy_features;
};

struct cpuinfo_x86
{
	__u8 x86;
	__u8 x86_vendor;
	__u8 x86_model;
	__u8 x86_stepping;
	int x86_tlbsize;
	__u32 vmx_capability[5];
	__u8 x86_virt_bits;
	__u8 x86_phys_bits;
	__u8 x86_coreid_bits;
	__u8 cu_id;
	__u32 extended_cpuid_level;
	int cpuid_level;
	union
	{
		__u32 x86_capability[21];
		long unsigned int x86_capability_alignment;
	};
	char x86_vendor_id[16];
	char x86_model_id[64];
	unsigned int x86_cache_size;
	int x86_cache_alignment;
	int x86_cache_max_rmid;
	int x86_cache_occ_scale;
	int x86_cache_mbm_width_offset;
	int x86_power;
	long unsigned int loops_per_jiffy;
	u64 ppin;
	u16 x86_max_cores;
	u16 apicid;
	u16 initial_apicid;
	u16 x86_clflush_size;
	u16 booted_cores;
	u16 phys_proc_id;
	u16 logical_proc_id;
	u16 cpu_core_id;
	u16 cpu_die_id;
	u16 logical_die_id;
	u16 cpu_index;
	bool smt_active;
	u32 microcode;
	u8 x86_cache_bits;
	unsigned int initialized : 1;
};

typedef struct
{
	arch_rwlock_t raw_lock;
	unsigned int magic;
	unsigned int owner_cpu;
	void *owner;
	struct lockdep_map dep_map;
} rwlock_t;

struct wait_queue_head
{
	spinlock_t lock;
	struct list_head head;
};
typedef struct wait_queue_head wait_queue_head_t;

enum pid_type
{
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

struct pid_namespace;

struct upid
{
	int nr;
	struct pid_namespace *ns;
};

struct pid
{
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[1];
};

typedef struct
{
	gid_t val;
} kgid_t;

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct
{
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
	struct lockdep_map lockdep_map;
};

struct workqueue_struct;

struct delayed_work
{
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

struct seqcount_raw_spinlock
{
	seqcount_t seqcount;
	raw_spinlock_t *lock;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

typedef struct
{
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

struct hrtimer_cpu_base;

struct hrtimer_clock_base
{
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)();
	ktime_t offset;
	long : 64;
	long : 64;
};

struct hrtimer_cpu_base
{
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active : 1;
	unsigned int in_hrtirq : 1;
	unsigned int hang_detected : 1;
	unsigned int softirq_activated : 1;
	unsigned int nr_events;
	short unsigned int nr_retries;
	short unsigned int nr_hangs;
	unsigned int max_hang_time;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	struct hrtimer_clock_base clock_base[8];
};

struct rlimit
{
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t();

typedef __restorefn_t *__sigrestore_t;

union sigval
{
	int sival_int;
	void *sival_ptr;
};

typedef union sigval sigval_t;

union __sifields
{
	struct
	{
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct
	{
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct
	{
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct
	{
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct
	{
		void *_addr;
		union
		{
			int _trapno;
			short int _addr_lsb;
			struct
			{
				char _dummy_bnd[8];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct
			{
				char _dummy_pkey[8];
				__u32 _pkey;
			} _addr_pkey;
			struct
			{
				long unsigned int _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct
	{
		long int _band;
		int _fd;
	} _sigpoll;
	struct
	{
		void *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};

struct kernel_siginfo
{
	struct
	{
		int si_signo;
		int si_errno;
		int si_code;
		union __sifields _sifields;
	};
};

struct sigaction
{
	__sighandler_t sa_handler;
	long unsigned int sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct k_sigaction
{
	struct sigaction sa;
};

struct mm_rss_stat
{
	atomic_long_t count[4];
};

struct cpu_itimer
{
	u64 expires;
	u64 incr;
};

struct task_cputime_atomic
{
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

struct thread_group_cputimer
{
	struct task_cputime_atomic cputime_atomic;
};

struct pacct_struct
{
	int ac_flag;
	long int ac_exitcode;
	long unsigned int ac_mem;
	u64 ac_utime;
	u64 ac_stime;
	long unsigned int ac_minflt;
	long unsigned int ac_majflt;
};

struct rw_semaphore
{
	atomic_long_t count;
	atomic_long_t owner;
	struct optimistic_spin_queue osq;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
	void *magic;
	struct lockdep_map dep_map;
};

struct core_state;

struct tty_struct;

struct taskstats;

struct tty_audit_buf;

struct signal_struct
{
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper : 1;
	unsigned int has_child_subreaper : 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct rseq
{
	__u32 cpu_id_start;
	__u32 cpu_id;
	__u64 rseq_cs;
	__u32 flags;
	long : 64;
};

struct rq;

struct rq_flags;

struct sched_class
{
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	void (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*check_preempt_curr)(struct rq *, struct task_struct *, int);
	struct task_struct *(*pick_next_task)(struct rq *);
	void (*put_prev_task)(struct rq *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	int (*balance)(struct rq *, struct task_struct *, struct rq_flags *);
	int (*select_task_rq)(struct task_struct *, int, int);
	struct task_struct *(*pick_task)(struct rq *);
	void (*migrate_task_rq)(struct task_struct *, int);
	void (*task_woken)(struct rq *, struct task_struct *);
	void (*set_cpus_allowed)(struct task_struct *, const struct cpumask *, u32);
	void (*rq_online)(struct rq *);
	void (*rq_offline)(struct rq *);
	struct rq *(*find_lock_rq)(struct task_struct *, struct rq *);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
	void (*task_change_group)(struct task_struct *);
};

typedef struct lockdep_map *lockdep_map_p;

struct maple_tree
{
	union
	{
		spinlock_t ma_lock;
		lockdep_map_p ma_external_lock;
	};
	void *ma_root;
	unsigned int ma_flags;
};

struct ldt_struct;

struct vdso_image;

typedef struct
{
	u64 ctx_id;
	atomic64_t tlb_gen;
	struct rw_semaphore ldt_usr_sem;
	struct ldt_struct *ldt;
	short unsigned int flags;
	struct mutex lock;
	void *vdso;
	const struct vdso_image *vdso_image;
	atomic_t perf_rdpmc_allowed;
	u16 pkey_allocation_map;
	s16 execute_only_pkey;
} mm_context_t;

struct xol_area;

struct uprobes_state
{
	struct xol_area *xol_area;
};

struct linux_binfmt;

struct kioctx_table;

struct user_namespace;

struct mm_struct
{
	struct
	{
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[46];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct *owner;
		struct user_namespace *user_ns;
		struct file *exe_file;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
	};
	long unsigned int cpu_bitmap[0];
};

struct swait_queue_head
{
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion
{
	unsigned int done;
	struct swait_queue_head wait;
};

struct kernel_cap_struct
{
	__u32 cap[2];
};

typedef struct kernel_cap_struct kernel_cap_t;

struct user_struct;

struct ucounts;

struct group_info;

struct cred
{
	atomic_t usage;
	atomic_t subscribers;
	void *put_addr;
	unsigned int magic;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	unsigned char jit_keyring;
	struct key *session_keyring;
	struct key *process_keyring;
	struct key *thread_keyring;
	struct key *request_key_auth;
	void *security;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union
	{
		int non_rcu;
		struct callback_head rcu;
	};
};

typedef int32_t key_serial_t;

typedef uint32_t key_perm_t;

struct key_type;

struct key_tag;

struct keyring_index_key
{
	long unsigned int hash;
	union
	{
		struct
		{
			u16 desc_len;
			char desc[6];
		};
		long unsigned int x;
	};
	struct key_type *type;
	struct key_tag *domain_tag;
	const char *description;
};

union key_payload
{
	void *rcu_data0;
	void *data[4];
};

struct assoc_array_ptr;

struct assoc_array
{
	struct assoc_array_ptr *root;
	long unsigned int nr_leaves_on_tree;
};

struct key_user;

struct key_restriction;

struct key
{
	refcount_t usage;
	key_serial_t serial;
	union
	{
		struct list_head graveyard_link;
		struct rb_node serial_node;
	};
	struct rw_semaphore sem;
	struct key_user *user;
	void *security;
	union
	{
		time64_t expiry;
		time64_t revoked_at;
	};
	time64_t last_used_at;
	kuid_t uid;
	kgid_t gid;
	key_perm_t perm;
	short unsigned int quotalen;
	short unsigned int datalen;
	short int state;
	long unsigned int flags;
	union
	{
		struct keyring_index_key index_key;
		struct
		{
			long unsigned int hash;
			long unsigned int len_desc;
			struct key_type *type;
			struct key_tag *domain_tag;
			char *description;
		};
	};
	union
	{
		union key_payload payload;
		struct
		{
			struct list_head name_link;
			struct assoc_array keys;
		};
	};
	struct key_restriction *restrict_link;
};

struct sighand_struct
{
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};

struct io_context
{
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
};

enum uprobe_task_state
{
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};

struct arch_uprobe_task
{
	long unsigned int saved_scratch_register;
	unsigned int saved_trap_nr;
	unsigned int saved_tf;
};

struct uprobe;

struct return_instance;

struct uprobe_task
{
	enum uprobe_task_state state;
	union
	{
		struct
		{
			struct arch_uprobe_task autask;
			long unsigned int vaddr;
		};
		struct
		{
			struct callback_head dup_xol_work;
			long unsigned int dup_xol_addr;
		};
	};
	struct uprobe *active_uprobe;
	long unsigned int xol_vaddr;
	struct return_instance *return_instances;
	unsigned int depth;
};

struct vm_struct
{
	struct vm_struct *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct kstat
{
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
	u32 dio_mem_align;
	u32 dio_offset_align;
};

struct kref
{
	refcount_t refcount;
};

struct rcu_segcblist
{
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	long int len;
	long int seglen[4];
	u8 flags;
};

struct srcu_node;

struct srcu_struct;

struct srcu_data
{
	long unsigned int srcu_lock_count[2];
	long unsigned int srcu_unlock_count[2];
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
	long : 64;
};

struct srcu_node
{
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};

struct srcu_struct
{
	struct srcu_node *node;
	struct srcu_node *level[3];
	int srcu_size_state;
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	unsigned int srcu_idx;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_gp_start;
	long unsigned int srcu_last_gp_end;
	long unsigned int srcu_size_jiffies;
	long unsigned int srcu_n_lock_retries;
	long unsigned int srcu_n_exp_nodelay;
	struct srcu_data *sda;
	bool sda_is_static;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	long unsigned int reschedule_jiffies;
	long unsigned int reschedule_count;
	struct delayed_work work;
	struct lockdep_map dep_map;
};

struct return_instance
{
	struct uprobe *uprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	struct return_instance *next;
};

struct vdso_image
{
	void *data;
	long unsigned int size;
	long unsigned int alt;
	long unsigned int alt_len;
	long unsigned int extable_base;
	long unsigned int extable_len;
	const void *extable;
	long int sym_vvar_start;
	long int sym_vvar_page;
	long int sym_pvclock_page;
	long int sym_hvclock_page;
	long int sym_timens_page;
	long int sym_VDSO32_NOTE_MASK;
	long int sym___kernel_sigreturn;
	long int sym___kernel_rt_sigreturn;
	long int sym___kernel_vsyscall;
	long int sym_int80_landing_pad;
	long int sym_vdso32_sigreturn_landing_pad;
	long int sym_vdso32_rt_sigreturn_landing_pad;
};

struct xarray
{
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

typedef u32 errseq_t;

struct address_space_operations;

struct address_space
{
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct folio
{
	union
	{
		struct
		{
			long unsigned int flags;
			union
			{
				struct list_head lru;
				struct
				{
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct vfsmount;

struct path
{
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct fown_struct
{
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file_ra_state
{
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

struct file
{
	union
	{
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct userfaultfd_ctx;

struct vm_userfaultfd_ctx
{
	struct userfaultfd_ctx *ctx;
};

struct anon_vma_name
{
	struct kref kref;
	char name[0];
};

struct anon_vma;

struct vm_operations_struct;

struct vm_area_struct
{
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union
	{
		struct
		{
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

typedef unsigned int vm_fault_t;

enum page_entry_size
{
	PE_SIZE_PTE = 0,
	PE_SIZE_PMD = 1,
	PE_SIZE_PUD = 2,
};

struct vm_fault;

struct vm_operations_struct
{
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char *(*name)(struct vm_area_struct *);
	int (*set_policy)(struct vm_area_struct *, struct mempolicy *);
	struct mempolicy *(*get_policy)(struct vm_area_struct *, long unsigned int);
	struct page *(*find_special_page)(struct vm_area_struct *, long unsigned int);
};

struct iovec
{
	void *iov_base;
	__kernel_size_t iov_len;
};

struct kvec
{
	void *iov_base;
	size_t iov_len;
};

struct bio_vec
{
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct iov_iter
{
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union
	{
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union
	{
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
		struct xarray *xarray;
		struct pipe_inode_info *pipe;
		void *ubuf;
	};
	union
	{
		long unsigned int nr_segs;
		struct
		{
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct wait_page_queue;

struct kiocb
{
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct hlist_bl_node;

struct hlist_bl_head
{
	struct hlist_bl_node *first;
};

struct hlist_bl_node
{
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct lockref
{
	union
	{
		struct
		{
			spinlock_t lock;
			int count;
		};
	};
};

struct qstr
{
	union
	{
		struct
		{
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct dentry_operations;

struct dentry
{
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union
	{
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union
	{
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct posix_acl;

struct inode_operations;

struct bdi_writeback;

struct file_lock_context;

struct cdev;

struct fsnotify_mark_connector;

struct inode
{
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union
	{
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union
	{
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union
	{
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union
	{
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	void *i_private;
};