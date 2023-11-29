#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef signed char __s8;

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

enum {
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

typedef u64 uint64_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

typedef unsigned int fmode_t;

typedef u64 phys_addr_t;

typedef long unsigned int irq_hw_number_t;

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	s64 counter;
} atomic64_t;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct hlist_node;

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct kernel_symbol {
	long unsigned int value;
	const char *name;
	const char *namespace;
};

typedef atomic64_t atomic_long_t;

typedef int (*initcall_t)();

struct lock_class_key {};

struct fs_context;

struct fs_parameter_spec;

struct dentry;

struct super_block;

struct module;

struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
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

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

struct qspinlock {
	union {
		atomic_t val;
		struct {
			u8 locked;
			u8 pending;
		};
		struct {
			u16 locked_pending;
			u16 tail;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;

struct qrwlock {
	union {
		atomic_t cnts;
		struct {
			u8 wlocked;
			u8 __lstate[3];
		};
	};
	arch_spinlock_t wait_lock;
};

typedef struct qrwlock arch_rwlock_t;

struct lockdep_map {};

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	long unsigned int begin;
	long unsigned int flags;
};

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct kref {
	refcount_t refcount;
};

struct kset;

struct kobj_type;

struct kernfs_node;

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module_param_attrs;

struct completion;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct optimistic_spin_queue {
	atomic_t tail;
};

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};

struct module_layout {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node mtn;
};

struct mod_section {
	int shndx;
	int num_entries;
	int max_entries;
};

struct plt_entry;

struct mod_arch_specific {
	struct mod_section got;
	struct mod_section plt;
	struct mod_section plt_idx;
	struct plt_entry *ftrace_trampolines;
};

struct elf64_sym;

typedef struct elf64_sym Elf64_Sym;

struct mod_kallsyms {
	Elf64_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

struct module_attribute;

struct kernel_param;

struct exception_table_entry;

struct bug_entry;

struct module_sect_attrs;

struct module_notes_attrs;

struct tracepoint;

typedef struct tracepoint * const tracepoint_ptr_t;

struct srcu_struct;

struct bpf_raw_event_map;

struct trace_event_call;

struct trace_eval_map;

struct module {
	enum module_state state;
	struct list_head list;
	char name[56];
	unsigned char build_id[20];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct module_layout core_layout;
	struct module_layout init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
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

struct static_call_key {
	void *func;
};

struct file_operations {
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

struct bug_entry {
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};

struct static_call_key {
	void *func;
};

struct bug_entry {
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};

typedef __s64 time64_t;

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
};

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

struct cpumask {
	long unsigned int bits[1];
};

typedef struct cpumask cpumask_t;

typedef struct cpumask cpumask_var_t[1];

struct seq_operations;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

union fpureg {
	__u32 val32[8];
	__u64 val64[4];
};

struct loongarch_fpu {
	unsigned int fcsr;
	uint64_t fcc;
	union fpureg fpr[32];
};

struct loongarch_vdso_info;

struct thread_struct {
	long unsigned int reg01;
	long unsigned int reg03;
	long unsigned int reg22;
	long unsigned int reg23;
	long unsigned int reg24;
	long unsigned int reg25;
	long unsigned int reg26;
	long unsigned int reg27;
	long unsigned int reg28;
	long unsigned int reg29;
	long unsigned int reg30;
	long unsigned int reg31;
	long unsigned int sched_ra;
	long unsigned int sched_cfa;
	long unsigned int csr_prmd;
	long unsigned int csr_crmd;
	long unsigned int csr_euen;
	long unsigned int csr_ecfg;
	long unsigned int csr_badvaddr;
	long unsigned int scr0;
	long unsigned int scr1;
	long unsigned int scr2;
	long unsigned int scr3;
	long unsigned int eflags;
	long unsigned int trap_nr;
	long unsigned int error_code;
	struct loongarch_vdso_info *vdso;
	long: 64;
	struct loongarch_fpu fpu;
	long: 64;
	long: 64;
};

typedef unsigned int vm_fault_t;

struct vm_fault;

struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
};

struct loongarch_vdso_info {
	void *vdso;
	long unsigned int size;
	long unsigned int offset_sigreturn;
	struct vm_special_mapping code_mapping;
	struct vm_special_mapping data_mapping;
};

struct task_struct;

struct pt_regs;

struct thread_info {
	struct task_struct *task;
	long unsigned int flags;
	long unsigned int tp_value;
	__u32 cpu;
	int preempt_count;
	struct pt_regs *regs;
	long unsigned int syscall;
	long unsigned int syscall_work;
};

struct llist_node {
	struct llist_node *next;
};

struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
	u16 src;
	u16 dst;
};

struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};

struct util_est {
	unsigned int enqueued;
	unsigned int ewma;
};

struct sched_avg {
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

struct sched_entity {
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg;
};

struct rt_rq;

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
	struct sched_rt_entity *parent;
	struct rt_rq *rt_rq;
	struct rt_rq *my_q;
};

typedef s64 ktime_t;

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};

struct sched_dl_entity {
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct sched_dl_entity *pi_se;
};

struct sched_statistics {
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

struct sched_info {
	long unsigned int pcount;
	long long unsigned int run_delay;
	long long unsigned int last_arrival;
	long long unsigned int last_queued;
};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct rb_root {
	struct rb_node *rb_node;
};

struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

struct posix_cputimer_base {
	u64 nextevt;
	struct timerqueue_head tqhead;
};
