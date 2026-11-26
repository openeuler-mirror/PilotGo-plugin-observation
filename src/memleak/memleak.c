// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

#include <sys/eventfd.h>
#include <sys/wait.h>
#include <sys/param.h>

#define DEFAULT_MIN_AGE_NS 500

static struct env
{
    int interval;
    int nr_intervals;
    pid_t pid;
    bool pid_from_child;
    bool trace_all;
    bool show_allocs;
    bool combined_only;
    int64_t min_age_ns;
    uint64_t sample_rate;
    int top_stacks;
    size_t min_size;
    size_t max_size;
    char object[32];

    bool wa_missing_free;
    bool percpu;
    int perf_max_stack_depth;
    int stack_map_max_entries;
    long page_size;
    bool kernel_trace;
    bool verbose;
    char command[32];
} env = {
    .interval = 5,
    .nr_intervals = -1,
    .pid = -1,
    .min_age_ns = DEFAULT_MIN_AGE_NS,
    .sample_rate = 1,
    .top_stacks = 10,
    .max_size = -1,
    .perf_max_stack_depth = 127,
    .stack_map_max_entries = 10240,
    .page_size = -1,
    .kernel_trace = true,
};

struct allocation_node
{
    uint64_t address;
    size_t size;
    struct allocation_node *next;
};

struct allocation
{
    uint64_t stack_id;
    size_t size;
    size_t count;
    struct allocation_node *allocations;
};

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
    do                                                           \
    {                                                            \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,                \
                    .func_name = #sym_name,                      \
                    .retprobe = is_retprobe);                    \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
            skel->progs.prog_name,                               \
            env.pid,                                             \
            env.object,                                          \
            0,                                                   \
            &uprobe_opts);                                       \
    } while (false);

#define __CHECK_PROGRAM(skel, prog_name)                   \
    do                                                     \
    {                                                      \
        if (!skel->links.prog_name)                        \
        {                                                  \
            perror("No program attached for " #prog_name); \
            return -errno;                                 \
        }                                                  \
    } while (false);

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do                                                                  \
    {                                                                   \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
        __CHECK_PROGRAM(skel, prog_name);                               \
    } while (false);

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

static volatile sig_atomic_t exiting;
static volatile bool child_exited = false;

static void sig_handler(int signo)
{
    if (signo == SIGCHLD)
        child_exited = 1;

    exiting = 1;
}

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
    "Trace outstanding memory allocations\n"
    "\n"
    "USAGE: memleak [-h] [-c COMMAND] [-p PID] [-t] [-n] [-a] [-o AGE_MS] [-C] [-F] [-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJECT] [-P] [INTERVAL] [INTERVALS]\n"
    "\n"
    "EXAMPLES:\n"
    "./memleak -p $(pidof allocs)\n"
    "        Trace allocations and display a summary of 'leaked' (outstanding)\n"
    "        allocations every 5 seconds\n"
    "./memleak -p $(pidof allocs) -t\n"
    "        Trace allocations and display each individual allocator function call\n"
    "./memleak -ap $(pidof allocs) 10\n"
    "        Trace allocations and display allocated addresses, sizes, and stacks\n"
    "        every 10 seconds for outstanding allocations\n"
    "./memleak -c './allocs'\n"
    "        Run the specified command and trace its allocations\n"
    "./memleak\n"
    "        Trace allocations in kernel mode and display a summary of outstanding\n"
    "        allocations every 5 seconds\n"
    "./memleak -o 60000\n"
    "        Trace allocations in kernel mode and display a summary of outstanding\n"
    "        allocations that are at least one minute (60 seconds) old\n"
    "./memleak -s 5\n"
    "        Trace roughly every 5th allocation, to reduce overhead\n"
    "";

#define OPT_PERF_MAX_STACK_DEPTH 1  /* --perf-max-stack-depth */
#define OPT_STACK_MAP_MAX_ENTRIES 2 /* --stack-map-max-entries */

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "process ID to trace. If not specified, trace kernel allocs"},
    {"trace", 't', 0, 0, "print trace message for each alloc/free alloc"},
    {"show-allocs", 'a', 0, 0, "show allocation addresses and sizes as well as call stacks"},
    {"older", 'o', "AGE_MS", 0, "prune allocations younger than this age in milliseconds"},
    {"command", 'c', "COMMAND", 0, "execute and trace the specified command"},
    {"combined-only", 'C', 0, 0, "show combined allocation statistics only"},
    {"wa-missing-only", 'F', 0, 0, "workaround to alleviate misjudgments when free is missing"},
    {"sample-rate", 's', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease to overhead"},
    {"top", 'T', "TOP_STACKS", 0, "display only this many top allocationg stacks (by size)"},
    {"min-size", 'z', "MIN_SIZE", 0, "capture only allocations larger than this size"},
    {"max-size", 'Z', "MAX_SIZE", 0, "capture only allocations smaller than this size"},
    {"obj", 'O', "OBJECT", 0, "attach to allocator functions in the specified object"},
    {"percpu", 'P', NULL, 0, "trace percpu allocations"},
    {"perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "PERF_MAX_STACK_DEPTH",
     0, "The limit for both kernel and user stack traces (default 127)"},
    {"stack-map-max-entries", OPT_STACK_MAP_MAX_ENTRIES, "STACK_MAP_MAX_ENTRIES",
     0, "The number of unique stack traces that can be stored and displayed (default 10240)"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show this full help"},
    {}};

static uint64_t *stack;
static struct allocation *allocs;
static const char default_object[] = "libc.so.6";

static void parse_positional(int *pos_args, int key, char *arg,
			     struct argp_state *state)
{
	if (*pos_args == 0) {
		env.interval = argp_parse_long(key, arg, state);
	} else if (*pos_args == 1) {
		env.nr_intervals = argp_parse_long(key, arg, state);
	} else {
		warning("Unrecognized positional argument: %s\n", arg);
		argp_usage(state);
	}
	(*pos_args)++;
}

static void finalize_args(struct argp_state *state)
{
	if (env.min_size > env.max_size) {
		warning("min size (-z) can't greater than max size (-Z)\n");
		argp_usage(state);
	}
	if (env.combined_only && env.min_age_ns != DEFAULT_MIN_AGE_NS)
		warning("Ignore min age ns for combined allocs\n");
}

static void parse_arg_extra(void)
{
	    static int pos_args = 0;
	    switch (key)
	    {
	    case 'p':
	        env.pid = argp_parse_pid(key, arg, state);
	        break;
	    case 't':
	        env.trace_all = true;
	        break;
	    case 'a':
	        env.show_allocs = true;
	        break;
	    case 'o':
	        env.min_age_ns = 1e6 * argp_parse_long(key, arg, state);
	        break;
	    case 'c':
	        strncpy(env.command, arg, sizeof(env.command) - 1);
	        break;
	    case 'C':
	        env.combined_only = true;
	        break;
	    case 'F':
	        env.wa_missing_free = true;
	        break;
	    case 's':
	        env.sample_rate = argp_parse_long(key, arg, state);
	        break;
	    case 'T':
	        env.top_stacks = argp_parse_long(key, arg, state);
	        break;
	    case 'z':
	        env.min_size = argp_parse_long(key, arg, state);
	        break;
	    case 'Z':
	        env.max_size = argp_parse_long(key, arg, state);
	        break;
	    case 'O':
	        strncpy(env.object, arg, sizeof(env.object) - 1);
	        break;
	    case 'P':
	        env.percpu = true;
	        break;
	    case 'v':
	        env.verbose = true;
	        break;
	    case 'h':
	        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
	        break;
	    case OPT_PERF_MAX_STACK_DEPTH:
	        env.perf_max_stack_depth = argp_parse_long(key, arg, state);
	        break;
	    case OPT_STACK_MAP_MAX_ENTRIES:
	        env.stack_map_max_entries = argp_parse_long(key, arg, state);
	        break;
	    case ARGP_KEY_ARG:
	        parse_positional(&pos_args, key, arg, state);
	        break;
	    case ARGP_KEY_END:
	        finalize_args(state);
	        break;
	    default:
	        return ARGP_ERR_UNKNOWN;
	    }
	    return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	parse_arg_extra();
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void event_init_extra(void)
{
	    if (!fd)
	    {
	        warning("Pointer to fd is NULL\n");
	        return 1;
	    }
	    const int temp_fd = eventfd(0, EFD_CLOEXEC);
	    if (temp_fd < 0)
	    {
	        perror("Failed to create event fd");
	        return -errno;
	    }
	    *fd = temp_fd;
	    return 0;
}

static int event_init(int *fd)
{
	event_init_extra();
}

static void event_wait_extra(void)
{
	    uint64_t event = 0;
	    const ssize_t bytes = read(fd, &event, sizeof(event));
	    if (bytes < 0)
	    {
	        perror("Failed to read from fd");
	        return -errno;
	    }
	    else if (bytes != sizeof(event))
	    {
	        warning("Read unexpected size\n");
	        return 1;
	    }
	    if (event != expected_event)
	    {
	        warning("Read event %lu, expected %lu\n", event, expected_event);
	        return 1;
	    }
	    return 0;
}

static int event_wait(int fd, uint64_t expected_event)
{
	event_wait_extra();
}

static void event_notify_extra(void)
{
	    const ssize_t bytes = write(fd, &event, sizeof(event));
	    if (bytes < 0)
	    {
	        perror("Failed to write to fd");
	        return -errno;
	    }
	    else if (bytes != sizeof(event))
	    {
	        warning("attempted to write %zu bytes, wrote %zd bytes\n", sizeof(event), bytes);
	        return 1;
	    }
	    return 0;
}

static int event_notify(int fd, uint64_t event)
{
	event_notify_extra();
}

static void fork_sync_exec_extra(void)
{
	    const pid_t pid = fork();
	    switch (pid)
	    {
	    case -1:
	        perror("Failed to create child process");
	        break;
	    case 0:
	    {
	        const uint64_t event = 1;
	        if (event_wait(fd, event))
	        {
	            warning("Failed to wait on event\n");
	            exit(EXIT_FAILURE);
	        }
	        printf("Received go event. executing child command\n");
	        const int err = execl(command, command, NULL);
	        if (err)
	        {
	            perror("Failed to execute child command");
	            return -1;
	        }
	        break;
	    }
	    default:
	        printf("child created with pid: %d\n", pid);
	        break;
	    }
	    return pid;
}

static void fork_sync_exec_extra(void)
{
	    const pid_t pid = fork();
	    switch (pid)
	    {
	    case -1:
	        perror("Failed to create child process");
	        break;
	    case 0:
	    {
	        const uint64_t event = 1;
	        if (event_wait(fd, event))
	        {
	            warning("Failed to wait on event\n");
	            exit(EXIT_FAILURE);
	        }
	        printf("Received go event. executing child command\n");
	        const int err = execl(command, command, NULL);
	        if (err)
	        {
	            perror("Failed to execute child command");
	            return -1;
	        }
	        break;
	    }
	    default:
	        printf("child created with pid: %d\n", pid);
	        break;
	    }
	    return pid;
}

static pid_t fork_sync_exec(const char *command, int fd)
{
	fork_sync_exec_extra();
}

static void (*print_stack_frames_func)();

#if USE_BLAZESYM
static blazesym *symbolizer;
static blazesym_sym_src_cfg src_cfg;

static void print_stack_frame_by_blazesym(size_t frame, uint64_t addr, const blazesym_csym *sym)
{
    if (!sym)
        printf("\t%5zu [<%016lx>] <%s>\n", frame, addr, "null sym");
    else if (sym->path && strlen(sym->path))
        printf("\t%5zu [<%016lx>] %s+0x%lx %s:%ld\n", frame, addr, sym->symbol, addr - sym->start_address, sym->path, sym->line_no);
    else
        printf("\t%5zu [<%016lx>] %s+0x%lx\n", frame, addr, sym->symbol, addr - sym->start_address);
}

static void print_stack_frames_by_blazesym_extra(void)
{
	    const blazesym_result *result = blazesym_symbolize(symbolizer, &src_cfg, 1, stack, env.perf_max_stack_depth);
	    for (size_t i = 0; i < result->size; i++)
	    {
	        const uint64_t addr = stack[i];
	        if (!addr)
	            break;
	        // no symbol found
	        if (!result || i >= result->size || result->entries[i].size == 0)
	        {
	            print_stack_frame_by_blazesym(i, addr, NULL);
	            continue;
	        }
	        // single symbol found
	        if (result->entries[i].size == 1)
	        {
	            const blazesym_csym *sym = &result->entries[i].syms[0];
	            print_stack_frame_by_blazesym(i, addr, sym);
	            continue;
	        }
	        // multi symbol found
	        printf("\t%zu [<%016lx>] (%lu entries)\n", i, addr, result->entries[i].size);
	        for (size_t j = 0; j < result->entries[i].size; j++)
	        {
	            const blazesym_csym *sym = &result->entries[i].syms[j];
	            if (sym->path && strlen(sym->path))
	                printf("\t\t%s@0x%lx %s:%ld\n", sym->symbol, sym->start_address, sym->path, sym->line_no);
	            else
	                printf("\t\t%s@0x%lx\n", sym->symbol, sym->start_address);
	        }
	    }
	    blazesym_result_free(result);
}

static void print_stack_frames_by_blazesym()
{
	print_stack_frames_by_blazesym_extra();
}
#else
struct syms_cache *syms_cache;
struct ksyms *ksyms;

static void print_stack_frames_by_ksyms_extra(void)
{
	    for (size_t i = 0; i < env.perf_max_stack_depth; i++)
	    {
	        const uint64_t addr = stack[i];
	        if (!addr)
	            break;
	        const struct ksym *ksym = ksyms__map_addr(ksyms, addr);
	        if (ksym)
	            printf("\t%zu [<%016lx>] %s+0x%lx\n", i, addr, ksym->name, addr - ksym->addr);
	        else
	            printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
	    }
}

static void print_stack_frames_by_ksyms()
{
	print_stack_frames_by_ksyms_extra();
}

static void print_stack_frames_by_syms_cache_extra(void)
{
	    const struct syms *syms = syms_cache__get_syms(syms_cache, env.pid);
	    if (!syms)
	    {
	        warning("Failed to get syms\n");
	        return;
	    }
	    for (size_t i = 0; i < env.perf_max_stack_depth; i++)
	    {
	        const uint64_t addr = stack[i];
	        if (!addr)
	            break;
	        char *dso_name;
	        uint64_t dso_offset;
	        const struct sym *sym = syms__map_addr_dso(syms, addr, &dso_name, &dso_offset);
	        if (sym)
	        {
	            printf("\t%zu [<%016lx>] %s+0x%lx", i, addr, sym->name, sym->offset);
	            if (dso_name)
	                printf(" [%s]", dso_name);
	            printf("\n");
	        }
	        else
	        {
	            printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
	        }
	    }
}

static void print_stack_frames_by_syms_cache()
{
	print_stack_frames_by_syms_cache_extra();
}
#endif

static void print_stack_frames_extra(void)
{
	    for (size_t i = 0; i < nr_allocs; i++)
	    {
	        const struct allocation *alloc = &allocs[i];
	        printf("%zu bytes in %zu allocations from stack\n", alloc->size, alloc->count);
	        if (env.show_allocs)
	        {
	            struct allocation_node *it = alloc->allocations;
	            while (!it)
	            {
	                printf("\taddr = %#lx size = %zu\n", it->address, it->size);
	                it = it->next;
	            }
	        }
	        if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack))
	        {
	            if (errno == ENOENT)
	                continue;
	            perror("Failed to lookup stack trace");
	            return -errno;
	        }
	        (*print_stack_frames_func)();
	    }
	    return 0;
}

static int print_stack_frames(struct allocation *allocs, size_t nr_allocs, int stack_traces_fd)
{
	print_stack_frames_extra();
}

static int alloc_size_compare(const void *a, const void *b)
{
    const struct allocation *x = (struct allocation *)a;
    const struct allocation *y = (struct allocation *)b;

    if (x->size > y->size)
        return -1;

    if (x->size < y->size)
        return 1;

    return 0;
}

static struct allocation_node *new_alloc_node(uint64_t address, size_t size,
					      struct allocation_node *next)
{
	struct allocation_node *node = malloc(sizeof(struct allocation_node));

	if (!node) {
		perror("malloc failed");
		return NULL;
	}
	node->address = address;
	node->size = size;
	node->next = next;
	return node;
}

static int merge_alloc(size_t *nr_allocs, uint64_t addr,
		       const struct alloc_info *info)
{
	/* when the stack_id exists in the allocs array,
	 * increment size with info->size */
	for (size_t i = 0; i < *nr_allocs; i++) {
		struct allocation *alloc = &allocs[i];

		if (alloc->stack_id != info->stack_id)
			continue;

		alloc->size += info->size;
		alloc->count++;

		if (env.show_allocs) {
			struct allocation_node *node =
				new_alloc_node(addr, info->size, alloc->allocations);

			if (!node)
				return -errno;
			alloc->allocations = node;
		}
		return 1;
	}
	return 0;
}

static int add_alloc(size_t *nr_allocs, uint64_t addr,
		     const struct alloc_info *info)
{
	struct allocation alloc = {
		.stack_id = info->stack_id,
		.size = info->size,
		.count = 1,
	};

	if (env.show_allocs) {
		struct allocation_node *node = new_alloc_node(addr, info->size, NULL);

		if (!node)
			return -errno;
		alloc.allocations = node;
	}

	memcpy(&allocs[*nr_allocs], &alloc, sizeof(alloc));
	(*nr_allocs)++;
	return 0;
}

static void reset_allocs_extra(void)
{
		/* Reset allocs list so that we dont accidentaly reuse data the next
		 * time we call this function */
		for (size_t i = 0; i < nr_allocs; i++) {
			allocs[i].stack_id = 0;
			if (env.show_allocs) {
				struct allocation_node *it = allocs[i].allocations;
				while (!it) {
					struct allocation_node *this = it;
					it = it->next;
					free(this);
				}
				allocs[i].allocations = NULL;
			}
		}
}

static void reset_allocs(size_t nr_allocs)
{
	reset_allocs_extra();
}

static void print_outstanding_allocs_extra(void)
{
	    time_t t = time(NULL);
	    struct tm *tm = localtime(&t);
	    size_t nr_allocs = 0;
	    // for each struct alloc_info "alloc_info" in the bpf map "allocs"
	    for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key)
	    {
	        struct alloc_info alloc_info = {};
	        int ret;
	        if (bpf_map_get_next_key(allocs_fd, &prev_key, &curr_key))
	        {
	            if (errno == ENOENT)
	                break;
	            perror("map get next key error");
	            return -errno;
	        }
	        if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info))
	        {
	            if (errno == ENOENT)
	                continue;
	            perror("map lookup error");
	            return -errno;
	        }
	        // filter by age
	        if (get_ktime_ns() - env.min_age_ns < alloc_info.timestamp_ns)
	            continue;
	        // filter invalid stacks
	        if (alloc_info.stack_id < 0)
	            continue;
	        ret = merge_alloc(&nr_allocs, curr_key, &alloc_info);
	        if (ret < 0)
	            return ret;
	        if (ret > 0)
	            continue;
	        ret = add_alloc(&nr_allocs, curr_key, &alloc_info);
	        if (ret < 0)
	            return ret;
	        if (nr_allocs > ALLOCS_MAX_ENTRIES)
	            break;
	    }
	    // sort the allocs array in descending order
	    qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);
	    // get min of allocs we stored vs the top N requested stacks
	    size_t nr_allocs_to_show = MIN(nr_allocs, env.top_stacks);
	    if (nr_allocs_to_show)
	    {
	        printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
	               tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs_to_show);
	        print_stack_frames(allocs, nr_allocs_to_show, stack_traces_fd);
	        reset_allocs(nr_allocs);
	    }
	    return 0;
}

static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd)
{
	print_outstanding_allocs_extra();
}

static void print_outstanding_combined_allocs_extra(void)
{
	    time_t t = time(NULL);
	    struct tm *tm = localtime(&t);
	    size_t nr_allocs = 0;
	    // for each stack_id "curr_key" and union combined_alloc_info "alloc"
	    // in bpf_map "combined_allocs"
	    for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key)
	    {
	        union combined_alloc_info combined_alloc_info = {};
	        if (bpf_map_get_next_key(combined_allocs_fd, &prev_key, &curr_key))
	        {
	            if (errno == ENOENT)
	                break;
	            perror("Map get next key error");
	            return -errno;
	        }
	        if (bpf_map_lookup_elem(combined_allocs_fd, &curr_key, &combined_alloc_info))
	        {
	            if (errno == ENOENT)
	                continue;
	            perror("map lookup error");
	            return -errno;
	        }
	        const struct allocation alloc = {
	            .stack_id = curr_key,
	            .size = combined_alloc_info.total_size,
	            .count = combined_alloc_info.number_of_allocs,
	        };
	        memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
	        if (++nr_allocs > COMBINED_ALLOCS_MAX_ENTRIES)
	            break;
	    }
	    qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);
	    // get min of allocs we stored vs the top N requested stacks
	    nr_allocs = MIN(nr_allocs, env.top_stacks);
	    if (nr_allocs)
	    {
	        printf("[%d:%d:%d] Top %zd stacks with outstanding allocations:\n",
	               tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs);
	        print_stack_frames(allocs, nr_allocs, stack_traces_fd);
	    }
	    return 0;
}

static int print_outstanding_combined_allocs(int combined_allocs_fd, int stack_traces_fd)
{
	print_outstanding_combined_allocs_extra();
}

bool has_kernel_node_tracepoints()
{
    return tracepoint_exists("kmem", "kmalloc_node") &&
           tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

static void disable_prog(struct bpf_program *prog)
{
	bpf_program__set_autoload(prog, false);
}

void disable_kernel_node_tracepoints(struct memleak_bpf *skel)
{
	disable_prog(skel->progs.memleak__kmalloc_node);
	disable_prog(skel->progs.memleak__kmem_cache_alloc_node);
}

void disable_kernel_percpu_tracepoints(struct memleak_bpf *skel)
{
	disable_prog(skel->progs.memleak__percpu_alloc_percpu);
	disable_prog(skel->progs.memleak__percpu_free_percpu);
}

void disable_kernel_tracepoints(struct memleak_bpf *skel)
{
	disable_prog(skel->progs.memleak__kmalloc);
	disable_prog(skel->progs.memleak__kmalloc_node);
	disable_prog(skel->progs.memleak__kfree);
	disable_prog(skel->progs.memleak__kmem_cache_alloc);
	disable_prog(skel->progs.memleak__kmem_cache_alloc_node);
	disable_prog(skel->progs.memleak__kmem_cache_free);
	disable_prog(skel->progs.memleak__mm_page_alloc);
	disable_prog(skel->progs.memleak__mm_page_free);
	disable_prog(skel->progs.memleak__percpu_alloc_percpu);
	disable_prog(skel->progs.memleak__percpu_free_percpu);
}

static void attach_uprobes_extra(void)
{
	    ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	    ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
	    ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
	    ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);
	    ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
	    ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);
	    ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
	    ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);
	    ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
	    ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);
	    ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
	    ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);
	    ATTACH_UPROBE_CHECKED(skel, free, free_enter);
	    ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);
	    // the following probes are intentinally allowed to fail attachment
	    // deprecated in libc.so bionic
	    ATTACH_UPROBE(skel, valloc, valloc_enter);
	    ATTACH_URETPROBE(skel, valloc, valloc_exit);
	    // deprecated in libc.so bionic
	    ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
	    ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);
	    // add in C11
	    ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
	    ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);
	    return 0;
}

int attach_uprobes(struct memleak_bpf *skel)
{
	attach_uprobes_extra();
}

static int child_exec_event_fd = -1;

static void spawn_child_command_extra(void)
{
		if (env.pid >= 0) {
			warning("Can not specify both command and pid\n");
			return 1;
		}
		if (event_init(&child_exec_event_fd)) {
			warning("Failed to init child event\n");
			return 1;
		}
		const pid_t child_pid = fork_sync_exec(env.command, child_exec_event_fd);
		if (child_pid < 0) {
			perror("failed to spawn child process");
			return -errno;
		}
		env.pid = child_pid;
		env.pid_from_child = true;
		return 0;
}

static int spawn_child_command(void)
{
	spawn_child_command_extra();
}

static void init_symbolizer_extra(void)
{
	#ifdef USE_BLAZESYM
		symbolizer = blazesym_new();
		if (!symbolizer) {
			warning("Failed to load blazesym");
			return -ENOMEM;
		}
		print_stack_frames_func = print_stack_frames_by_blazesym;
	#else
		if (env.kernel_trace) {
			ksyms = ksyms__load();
			if (!ksyms) {
				warning("Failed to load ksyms\n");
				return -ENOMEM;
			}
			print_stack_frames_func = print_stack_frames_by_ksyms;
		} else {
			syms_cache = syms_cache__new(0);
			if (!syms_cache) {
				warning("Failed to create syms_cache\n");
				return -ENOMEM;
			}
			print_stack_frames_func = print_stack_frames_by_syms_cache;
		}
	#endif
		return 0;
}

static int init_symbolizer(void)
{
	init_symbolizer_extra();
}

static void reap_child_process_extra(void)
{
		if (!child_exited) {
			if (kill(env.pid, SIGTERM)) {
				perror("Failed to signal child process");
				return -errno;
			}
			printf("Signaled child process\n");
		}
		if (waitpid(env.pid, NULL, 0) < 0) {
			perror("Failed to reap child process");
			return -errno;
		}
		printf("reaped child process\n");
		return 0;
}

static int reap_child_process(void)
{
	reap_child_process_extra();
}

static void main_extra(void)
{
	    int ret = 0;
	    struct memleak_bpf *skel = NULL;
	    static const struct argp argp = {
	        .options = opts,
	        .parser = parse_arg,
	        .doc = argp_program_doc,
	    };
	    // parse command line args to env setting
	    ret = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	    if (ret)
	        return ret;
	    if (!bpf_is_root())
	        return 1;
	    if (signal(SIGINT, sig_handler) == SIG_ERR ||
	        signal(SIGCHLD, sig_handler) == SIG_ERR)
	    {
	        perror("Failed to setup signal handling");
	        return errno;
	    }
	    if (!strlen(env.object))
	    {
	        warning("Using default object: %s\n", default_object);
	        strncpy(env.object, default_object, sizeof(env.object) - 1);
	    }
	    env.page_size = sysconf(_SC_PAGE_SIZE);
	    printf("Using pages size %ld\n", env.page_size);
	    env.kernel_trace = env.pid < 0 && !strlen(env.command);
	    printf("tracing kernel: %s\n", env.kernel_trace ? "true" : "false");
	    // if specific userspace program was specified,
	    // create the child process and use an eventfd to synchronize to call to exec()
	    if (strlen(env.command))
	    {
	        ret = spawn_child_command();
	        if (ret)
	            return ret;
	    }
	    // allocate space for storing a stack trace
	    stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
	    if (!stack)
	    {
	        warning("Failed to allocate stack array\n");
	        return -ENOMEM;
	    }
	#ifdef USE_BLAZESYM
	    if (env.pid < 0)
	    {
	        src_cfg.src_type = BLAZESYM_SRC_T_KERNEL;
	        src_cfg.params.kernel.kallsyms = NULL;
	        src_cfg.params.kernel.kernel_image = NULL;
	    }
	    else
	    {
	        src_cfg.src_type = BLAZESYM_SRC_T_PROCESS;
	        src_cfg.params.process.pid = env.pid;
	    }
	#endif
	    // allocate space for storing "allocation" structs
	    if (env.combined_only)
	        allocs = calloc(COMBINED_ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	    else
	        allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	    if (!allocs)
	    {
	        warning("Failed to allocate array\n");
	        ret = -ENOMEM;
	        goto cleanup;
	    }
	    libbpf_set_print(libbpf_print_fn);
	    skel = memleak_bpf__open();
	    if (!skel)
	    {
	        warning("Failed to open bpf object\n");
	        ret = 1;
	        goto cleanup;
	    }
	    skel->rodata->min_size = env.min_size;
	    skel->rodata->max_size = env.max_size;
	    skel->rodata->page_size = env.page_size;
	    skel->rodata->sample_rate = env.sample_rate;
	    skel->rodata->trace_all = env.trace_all;
	    skel->rodata->stack_flags = env.kernel_trace ? 0 : BPF_F_USER_STACK;
	    skel->rodata->wa_missing_free = env.wa_missing_free;
	    bpf_map__set_value_size(skel->maps.stack_traces,
	                            env.perf_max_stack_depth * sizeof(unsigned long));
	    bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_map_max_entries);
	    // disable kernel tracepoints based on setting or avaiability
	    if (env.kernel_trace)
	    {
	        if (!has_kernel_node_tracepoints())
	            disable_kernel_node_tracepoints(skel);
	        if (!env.percpu)
	            disable_kernel_percpu_tracepoints(skel);
	    }
	    else
	    {
	        disable_kernel_tracepoints(skel);
	    }
	    ret = memleak_bpf__load(skel);
	    if (ret)
	    {
	        warning("Failed to load BPF object\n");
	        goto cleanup;
	    }
	    const int allocs_fd = bpf_map__fd(skel->maps.allocs);
	    const int combined_allocs_fd = bpf_map__fd(skel->maps.combined_allocs);
	    const int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);
	    // if userspace oriented, attach uprobes
	    if (!env.kernel_trace)
	    {
	        ret = attach_uprobes(skel);
	        if (ret)
	        {
	            warning("Failed to attach uprobes\n");
	            goto cleanup;
	        }
	    }
	    ret = memleak_bpf__attach(skel);
	    if (ret)
	    {
	        warning("Failed to attach BPF programs\n");
	        goto cleanup;
	    }
	    // if running a specific userspace program,
	    // nitify the child process that it can exec its program
	    if (strlen(env.command))
	    {
	        ret = event_notify(child_exec_event_fd, 1);
	        if (ret)
	        {
	            warning("Failed to notify child to perform exec\n");
	            goto cleanup;
	        }
	    }
	    ret = init_symbolizer();
	    if (ret)
	        goto cleanup;
	    printf("Tracing outstanding memory allocs... Hit Ctrl-C to end\n");
	    // main loop
	    while (!exiting && env.nr_intervals)
	    {
	        env.nr_intervals--;
	        sleep(env.interval);
	        if (env.combined_only)
	            print_outstanding_combined_allocs(combined_allocs_fd, stack_traces_fd);
	        else
	            print_outstanding_allocs(allocs_fd, stack_traces_fd);
	    }
	    // after loop ends, check for child process and cleanup accordingly
	    if (env.pid > 0 && env.pid_from_child)
	    {
	        ret = reap_child_process();
	        if (ret)
	            goto cleanup;
	    }
	cleanup:
	#ifdef USE_BLAZESYM
	    blazesym_free(symbolizer);
	#else
	    if (syms_cache)
	        syms_cache__free(syms_cache);
	    if (ksyms)
	        ksyms__free(ksyms);
	#endif
	    memleak_bpf__destroy(skel);
	    free(allocs);
	    free(stack);
	    printf("done\n");
	    return ret;
}

int main(int argc, char *argv[])
{
	main_extra();
}