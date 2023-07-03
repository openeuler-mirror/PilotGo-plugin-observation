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

static error_t parse_arg(int key, char *arg, struct argp_state *state)
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
        if (pos_args == 0)
        {
            env.interval = argp_parse_long(key, arg, state);
        }
        else if (pos_args == 1)
        {
            env.nr_intervals = argp_parse_long(key, arg, state);
        }
        else
        {
            warning("Unrecognized positional argument: %s\n", arg);
            argp_usage(state);
        }
        pos_args++;
        break;
    case ARGP_KEY_END:
        if (env.min_size > env.max_size)
        {
            warning("min size (-z) can't greater than max size (-Z)\n");
            argp_usage(state);
        }
        if (env.combined_only && env.min_age_ns != DEFAULT_MIN_AGE_NS)
            warning("Ignore min age ns for combined allocs\n");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static int event_init(int *fd)
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

static int event_wait(int fd, uint64_t expected_event)
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

static int event_notify(int fd, uint64_t event)
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

static pid_t fork_sync_exec(const char *command, int fd)
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

static void print_stack_frames_by_blazesym()
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
#else
struct syms_cache *syms_cache;
struct ksyms *ksyms;
