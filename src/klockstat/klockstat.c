// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "klockstat.h"
#include "klockstat.skel.h"
#include "trace_helpers.h"
#include "compat.h"
#include <sys/param.h>

static struct prog_env {
    pid_t pid;
	pid_t tid;
    char *lock_name;
    bool per_thread;
}

static const char args_doc[] = "FUNCTION";
static const char argp_program_doc[] =;

static const struct argp_option opts[] = {
    {}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			  va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void enable_fentry(struct klockstat_bpf *obj)
{
	bool debug_lock;

	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_trylock, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_interruptible, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_killable, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_killable_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_unlock, false);

	bpf_program__set_autoload(obj->progs.kprobe_down_read, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_trylock, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_killable, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_killable_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_up_read, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_trylock, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_killable, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_killable_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_up_write, false);

	/**
	 * commit 31784cff7ee0 ("rwsem: Implement down_read_interruptible")
	 */
	if (!fentry_can_attach("down_read_interruptible", NULL)) {
		bpf_program__set_autoload(obj->progs.down_read_interruptible, false);
		bpf_program__set_autoload(obj->progs.down_read_interruptible_exit, false);
	}

	/* CONFIG_DEBUG_LOCK_ALLOC is on */
	debug_lock = fentry_can_attach("mutex_lock_nested", NULL);
	if (!debug_lock)
		return;

	bpf_program__set_attach_target(obj->progs.mutex_lock, 0,
				       "mutex_lock_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_exit, 0,
				       "mutex_lock_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_interruptible, 0,
				       "mutex_lock_interruptible_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_interruptible_exit, 0,
				       "mutex_lock_interruptible_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_killable, 0,
				       "mutex_lock_killable_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_killable_exit, 0,
				       "mutex_lock_killable_nested");

	bpf_program__set_attach_target(obj->progs.down_read, 0,
				       "down_read_nested");
	bpf_program__set_attach_target(obj->progs.down_read_exit, 0,
				       "down_read_nested");
	bpf_program__set_attach_target(obj->progs.down_read_killable, 0,
				       "down_read_killable_nested");
	bpf_program__set_attach_target(obj->progs.down_read_killable_exit, 0,
				       "down_read_killable_nested");
	bpf_program__set_attach_target(obj->progs.down_write, 0,
				       "down_write_nested");
	bpf_program__set_attach_target(obj->progs.down_write_exit, 0,
				       "down_write_nested");
	bpf_program__set_attach_target(obj->progs.down_write_killable, 0,
				       "down_write_killable_nested");
	bpf_program__set_attach_target(obj->progs.down_write_killable_exit, 0,
				       "down_write_killable_nested");
}

static void enable_kprobes(struct klockstat_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.mutex_lock, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_interruptible, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_killable, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_killable_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_unlock, false);

	bpf_program__set_autoload(obj->progs.down_read, false);
	bpf_program__set_autoload(obj->progs.down_read_exit, false);
	bpf_program__set_autoload(obj->progs.down_read_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.down_read_interruptible, false);
	bpf_program__set_autoload(obj->progs.down_read_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.down_read_killable, false);
	bpf_program__set_autoload(obj->progs.down_read_killable_exit, false);
	bpf_program__set_autoload(obj->progs.up_read, false);
	bpf_program__set_autoload(obj->progs.down_write, false);
	bpf_program__set_autoload(obj->progs.down_write_exit, false);
	bpf_program__set_autoload(obj->progs.down_write_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.down_write_killable, false);
	bpf_program__set_autoload(obj->progs.down_write_killable_exit, false);
	bpf_program__set_autoload(obj->progs.up_write, false);

	/**
	 * commit 31784cff7ee0 ("rwsem: Implement down_read_interruptible")
	 */
	if (!kprobe_exists("down_read_interruptible")) {
		bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible, false);
		bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible_exit, false);
	}
}

int main(int argc, char *argv[])
{
    static struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = argp_program_doc,
	};
    struct ksyms *ksyms = NULL;
    int err;
    void *lock_addr = NULL;

    err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

    if (!bpf_is_root())
		return 1;

    signal(SIGINT, sig_handler);
	libbpf_set_print(libbpf_print_fn);

    ksyms = ksyms__load();
	if (!ksyms) {
		warning("failed to load kallsyms\n");
		err = 1;
		goto cleanup;
	}
	if (env.lock_name) {
		lock_addr = get_lock_addr(ksyms, env.lock_name);
		if (!lock_addr) {
			warning("Failed to find lock %s\n", env.lock_name);
			err = 1;
			goto cleanup;
		}
	}

    obj = klockstat_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->target_tgid = env.pid;
	obj->rodata->target_pid = env.tid;
	obj->rodata->target_lock = lock_addr;
	obj->rodata->per_thread = env.per_thread;

	if (fentry_can_attach("mutex_locK", NULL) ||
	    fentry_can_attach("mutex_lock_nested", NULL))
		enable_fentry(obj);
	else
		enable_kprobes(obj);

cleanup:
    ksyms__free(ksyms);

    return err != 0;
}