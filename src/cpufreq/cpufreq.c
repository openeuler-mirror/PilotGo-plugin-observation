// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "cpufreq.h"
#include "cpufreq.skel.h"
#include "trace_helpers.h"
#include <linux/perf_event.h>
#include <sys/syscall.h>

static struct env {
	bool verbose;
	int freq;
	int duration;
	char *cgroupspath;
	bool cg;
} env = {
	.duration = -1,
	.freq = 99,
};

const char *argp_program_version = "cpufreq 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Sampling CPU freq system-wide & by process. Ctrl-C to end.\n"
"\n"
"USAGE: cpufreq [--help] [-d DURATION] [-f FREQUENCY] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    cpufreq         # sample CPU freq at 99HZ (default)\n"
"    cpufreq -d 5    # sample for 5 seconds only\n"
"    cpufreq -c CG   # Trace process under cgroupsPath CG\n"
"    cpufreq -f 199  # sample CPU freq at 199HZ\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to sample in seconds" },
	{ "frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static void parse_arg_extra(void)
{
		switch (key) {
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'd':
			errno = 0;
			env.duration = strtol(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				warning("Invalid duration: %s\n", arg);
				argp_usage(state);
			}
			break;
		case 'c':
			env.cgroupspath = arg;
			env.cg = true;
			break;
		case 'f':
			errno = 0;
			env.freq = strtol(arg, NULL, 10);
			if (errno || env.freq <= 0) {
				warning("Invalid freq (in HZ): %s\n", arg);
				argp_usage(state);
			}
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

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	for (int i = 0; i < nr_cpus; i++) {
		int fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);

		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			warning("Failed to init perf sampling: %s\n", strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			warning("Failed to attach perf event on cpu: #%d!\n", i);
			close(fd);
			return -1;
		}
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

static void sig_handler(int sig)
{}

static void init_freqs_mhz_extra(void)
{
		char path[64];
		FILE *f;
		for (int i = 0; i < nr_cpus; i++) {
			snprintf(path, sizeof(path),
				 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq",
				 i);
			f = fopen(path, "r");
			if (!f) {
				warning("Failed to open '%s': %s\n", path,
					strerror(errno));
				return -1;
			}
			if (fscanf(f, "%u\n", &freqs_mhz[i]) != 1) {
				warning("Failed to parse '%s': %s\n", path,
					strerror(errno));
				fclose(f);
				return -1;
			}
			/*
			 * scaling_cur_freq is in kHZ. to be handled with
			 * a small data size, it's converted in mHZ.
			 */
			freqs_mhz[i] /= 1000;
			fclose(f);
		}
		return 0;
}

static int init_freqs_mhz(__u32 *freqs_mhz, int nr_cpus)
{
	init_freqs_mhz_extra();
}

static void print_linear_hists(struct bpf_map *hists,
			       struct cpufreq_bpf__bss *bss)
{
	struct hkey lookup_key = {}, next_key;
	int err, fd = bpf_map__fd(hists);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			warning("Failed to lookup hist: %d\n", err);
			return;
		}
		print_linear_hist(hist.slots, MAX_SLOTS, 0, HIST_STEP_SIZE,
				  next_key.comm);
		printf("\n");
		lookup_key = next_key;
	}

	printf("\n");
	print_linear_hist(bss->syswide.slots, MAX_SLOTS, 0, HIST_STEP_SIZE,
			  "syswide");
}

static void get_nr_cpus_extra(void)
{
		int nr = libbpf_num_possible_cpus();
		if (nr < 0) {
			warning("Failed to get # of possible cpus: '%s'!\n",
				strerror(-nr));
			return -1;
		}
		if (nr > MAX_CPU_NR) {
			warning("the number of cpu cores is too big, please "
				"increase MAX_CPU_NR's value and recompile");
			return -1;
		}
		return nr;
}

static int get_nr_cpus(void)
{
	get_nr_cpus_extra();
}

static void set_probe_autoload(struct cpufreq_bpf *obj)
{
	if (probe_tp_btf("cpu_frequency"))
		bpf_program__set_autoload(obj->progs.cpu_frequency_raw, false);
	else
		bpf_program__set_autoload(obj->progs.cpu_frequency, false);
}

static void setup_cgroup_map_extra(void)
{
		int idx = 0;
		int cg_map_fd;
		if (!env.cg)
			return 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		*cgfd = open(env.cgroupspath, O_RDONLY);
		if (*cgfd < 0) {
			warning("Failed opening Cgroup path: %s", env.cgroupspath);
			return -1;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			return -1;
		}
		return 0;
}

static int setup_cgroup_map(struct cpufreq_bpf *obj, int *cgfd)
{
	setup_cgroup_map_extra();
}

static void main_extra(void)
{
		static const struct argp argp = {
			.parser = parse_arg,
			.options = opts,
			.doc = argp_program_doc,
		};
		struct bpf_link *links[MAX_CPU_NR] = {};
		struct cpufreq_bpf *obj;
		int err, cgfd = -1;
		err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
		if (err)
			return err;
		if (!bpf_is_root())
			return 1;
		libbpf_set_print(libbpf_print_fn);
		nr_cpus = get_nr_cpus();
		if (nr_cpus < 0)
			return 1;
		obj = cpufreq_bpf__open();
		if (!obj) {
			warning("Failed to open BPF object\n");
			return 1;
		}
		set_probe_autoload(obj);
		err = cpufreq_bpf__load(obj);
		if (err) {
			warning("Failed to load BPF object\n");
			goto cleanup;
		}
		if (!obj->bss) {
			warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
			goto cleanup;
		}
		err = init_freqs_mhz(obj->bss->freqs_mhz, nr_cpus);
		if (err) {
			warning("Failed to init freqs\n");
			goto cleanup;
		}
		obj->bss->filter_memcg = env.cg;
		if (setup_cgroup_map(obj, &cgfd))
			goto cleanup;
		err = open_and_attach_perf_event(env.freq, obj->progs.do_sample, links);
		if (err)
			goto cleanup;
		err = cpufreq_bpf__attach(obj);
		if (err) {
			warning("Failed to attach BPF programs\n");
			goto cleanup;
		}
		printf("Sampling CPU freq system-wide & by process. Ctrl-C to end.\n");
		signal(SIGINT, sig_handler);
		/*
		 * we'll get sleep interrupted when someone process Ctrl-C (which will
		 * be "handled" with noop by sig_handler).
		 */
		sleep(env.duration);
		printf("\n");
		print_linear_hists(obj->maps.hists, obj->bss);
	cleanup:
		for (int i = 0; i < nr_cpus; i++)
			bpf_link__destroy(links[i]);
		cpufreq_bpf__destroy(obj);
		if (cgfd > 0)
			close(cgfd);
		return err != 0;
}

int main(int argc, char *argv[])
{
	main_extra();
}
