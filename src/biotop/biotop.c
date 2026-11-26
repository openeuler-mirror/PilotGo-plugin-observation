// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "commons.h"
#include "biotop.h"
#include "biotop.skel.h"
#include "trace_helpers.h"
#include "compat.h"

#define OUTPUT_ROWS_LIMIT	10240

enum SORT {
	ALL,
	IO,
	BYTES,
	TIME,
};

struct disk {
	int major;
	int minor;
	char name[256];
};

struct vector {
	size_t nr;
	size_t capacity;
	void **elems;
};

static void grow_vector_extra(void)
{
		if (vector->nr >= vector->capacity) {
			void **reallocated;
			if (!vector->capacity)
				vector->capacity = 1;
			else
				vector->capacity *= 2;
			reallocated = libbpf_reallocarray(vector->elems, vector->capacity, sizeof(*vector->elems));
			if (!reallocated)
				return -1;
			vector->elems = reallocated;
		}
		return 0;
}

int grow_vector(struct vector *vector)
{
	grow_vector_extra();
}

void free_vector(struct vector vector)
{
	for (size_t i = 0; i < vector.nr; i++) {
		if (vector.elems[i] != NULL)
			free(vector.elems[i]);
	}

	free(vector.elems);
}

struct vector disks = {};

static volatile sig_atomic_t exiting;

static struct env {
	bool	clear_screen;
	int	output_rows;
	int	sort_by;
	int	interval;
	int	count;
	bool	verbose;
} env = {
	.clear_screen	= true,
	.output_rows	= 20,
	.sort_by	= ALL,
	.interval	= 1,
	.count		= 99999999,
	.verbose	= false,
};

const char *argp_program_version = "biotop 0.2";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace file reads/writes by process.\n"
"\n"
"USAGE: biotop [-h] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    biotop            # file I/O top, refresh every 1s\n"
"    biotop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "noclear", 'c', NULL, 0, "Don't clear the screen" },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, io, bytes, time]" },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static void parse_sort_arg_extra(void)
{
		if (!strcmp(arg, "all"))
			env.sort_by = ALL;
		else if (!strcmp(arg, "io"))
			env.sort_by = IO;
		else if (!strcmp(arg, "bytes"))
			env.sort_by = BYTES;
		else if (!strcmp(arg, "time"))
			env.sort_by = TIME;
		else {
			warning("Invalid sort method: %s\n", arg);
			argp_usage(state);
		}
}

static void parse_sort_arg(const char *arg, struct argp_state *state)
{
	parse_sort_arg_extra();
}

static void parse_rows_arg(const char *arg, struct argp_state *state)
{
	errno = 0;
	env.output_rows = strtol(arg, NULL, 10);
	if (errno || env.output_rows <= 0) {
		warning("Invalid rows: %s\n", arg);
		argp_usage(state);
	}
	if (env.output_rows > OUTPUT_ROWS_LIMIT)
		env.output_rows = OUTPUT_ROWS_LIMIT;
}

static void parse_positional_arg(const char *arg, int pos,
				 struct argp_state *state)
{
	long value;

	if (pos > 1) {
		warning("Unrecognized positional argument: %s\n", arg);
		argp_usage(state);
	}

	errno = 0;
	value = strtol(arg, NULL, 10);
	if (errno || value <= 0) {
		warning("Invalid %s\n", pos == 0 ? "interval" : "count");
		argp_usage(state);
	}

	if (pos == 0)
		env.interval = value;
	else
		env.count = value;
}

static void parse_arg_extra(void)
{
		static int pos_args;
		switch (key) {
		case 'c':
			env.clear_screen = false;
			break;
		case 's':
			parse_sort_arg(arg, state);
			break;
		case 'r':
			parse_rows_arg(arg, state);
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case ARGP_KEY_ARG:
			parse_positional_arg(arg, pos_args++, state);
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

static void sig_handler(int sig)
{
	exiting = 1;
}

struct data_t {
	struct info_t key;
	struct val_t value;
};

static void sort_column_extra(void)
{
		struct data_t *d1 = (struct data_t *)obj1;
		struct data_t *d2 = (struct data_t *)obj2;
		struct val_t *s1 = &d1->value;
		struct val_t *s2 = &d2->value;
		if (env.sort_by == IO)
			return s2->io - s1->io;
		else if (env.sort_by == BYTES)
			return s2->bytes - s1->bytes;
		else if (env.sort_by == TIME)
			return s2->us - s1->us;
		else
			return (s2->io + s2->bytes + s2->us)
				- (s1->io + s1->bytes + s1->us);
}

static int sort_column(const void *obj1, const void *obj2)
{
	sort_column_extra();
}

static void parse_disk_stat_extra(void)
{
		FILE *fp;
		char *line;
		size_t zero = 0;
		fp = fopen("/proc/diskstats", "r");
		if (!fp)
			return;
		while (getline(&line, &zero, fp) != -1) {
			struct disk disk;
			if (sscanf(line, "%d %d %s", &disk.major, &disk.minor, disk.name) != 3)
				continue;
			if (grow_vector(&disks) == -1)
				goto err;
			disks.elems[disks.nr] = malloc(sizeof(disk));
			if (!disks.elems[disks.nr])
				goto err;
			memcpy(disks.elems[disks.nr], &disk, sizeof(disk));
			disks.nr++;
		}
		free(line);
		fclose(fp);
		return;
	err:
		warning("Realloc or malloc failed\n");
		free_vector(disks);
}

static void parse_disk_stat(void)
{
	parse_disk_stat_extra();
}

static char *search_disk_name(int major, int minor)
{
	for (size_t i = 0; i < disks.nr; i++) {
		struct disk *diskp;

		if (!disks.elems[i])
			continue;

		diskp = (struct disk *)disks.elems[i];
		if (diskp->major == major && diskp->minor == minor)
			return diskp->name;
	}

	return "";
}

static void print_loadavg_extra(void)
{
		FILE *fp;
		fp = fopen("/proc/loadavg", "r");
		if (!fp)
			return;
		{
			char ts[16], buf[256] = {};
			int n;
			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			n = fread(buf, 1, sizeof(buf), fp);
			if (n)
				printf("%8s loadavg: %s\n", ts, buf);
		}
		fclose(fp);
}

static void print_loadavg(void)
{
	print_loadavg_extra();
}

static void print_stat_row_extra(void)
{
		const struct info_t *key = &data->key;
		const struct val_t *value = &data->value;
		float avg_ms = 0;
		/* To avoid floating point exception. */
		if (value->io)
			avg_ms = ((float)value->us) / 1000 / value->io;
		printf("%-7d %-16s %1s %-3d %-3d %-8s %5d %7lld %6.2f\n",
		       key->pid, key->name, key->rwflag ? "W" : "R",
		       key->major, key->minor,
		       search_disk_name(key->major, key->minor),
		       value->io, value->bytes / 1024, avg_ms);
}

static void print_stat_row(const struct data_t *data)
{
	print_stat_row_extra();
}

static void fetch_counts_extra(void)
{
		struct info_t *prev_key = NULL;
		int rows = 0, err;
		while (1) {
			err = bpf_map_get_next_key(fd, prev_key, &datas[rows].key);
			if (err) {
				if (errno == ENOENT)
					return rows;
				warning("bpf_map_get_next_key failed: %s\n",
					strerror(errno));
				return -1;
			}
			prev_key = &datas[rows].key;
			err = bpf_map_lookup_elem(fd, &datas[rows].key, &datas[rows].value);
			if (err) {
				warning("bpf_map_lookup_elem failed: %s\n",
					strerror(errno));
				return -1;
			}
			rows++;
		}
}

static int fetch_counts(int fd, struct data_t *datas)
{
	fetch_counts_extra();
}

static void clear_counts_extra(void)
{
		struct info_t *prev_key = NULL;
		struct info_t key;
		int err;
		while (1) {
			err = bpf_map_get_next_key(fd, prev_key, &key);
			if (err) {
				if (errno == ENOENT)
					return 0;
				warning("bpf_map_get_next_key failed: %s\n",
					strerror(errno));
				return err;
			}
			err = bpf_map_delete_elem(fd, &key);
			if (err) {
				warning("bpf_map_delete_elem failed: %s\n",
					strerror(errno));
				return err;
			}
			prev_key = &key;
		}
}

static int clear_counts(int fd)
{
	clear_counts_extra();
}

static void print_stat_extra(void)
{
		static struct data_t datas[OUTPUT_ROWS_LIMIT];
		int err, rows;
		int fd = bpf_map__fd(obj->maps.counts);
		print_loadavg();
		printf("%-7s %-16s %1s %-3s %-3s %-8s %5s %7s %6s\n",
		       "PID", "COMM", "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms");
		rows = fetch_counts(fd, datas);
		if (rows < 0)
			return -1;
		qsort(datas, rows, sizeof(struct data_t), sort_column);
		rows = rows < env.output_rows ? rows : env.output_rows;
		for (int i = 0; i < rows; i++)
			print_stat_row(&datas[i]);
		printf("\n");
		err = clear_counts(fd);
		if (err)
			return err;
		return 0;
}

static int print_stat(struct biotop_bpf *obj)
{
	print_stat_extra();
}

static int attach_io_probe(struct biotop_bpf *obj, struct bpf_program *prog,
			   struct bpf_link **link, const char *func,
			   const struct ksyms *ksyms)
{
	char alt_name[32];

	snprintf(alt_name, sizeof(alt_name), "__%s", func);
	if (ksyms__get_symbol(ksyms, alt_name))
		func = alt_name;

	*link = bpf_program__attach_kprobe(prog, false, func);
	if (!*link) {
		warning("Failed to load attach %s\n", func);
		return -1;
	}
	return 0;
}

static void main_extra(void)
{
		static const struct argp argp = {
			.options = opts,
			.parser = parse_arg,
			.doc = argp_program_doc,
		};
		struct biotop_bpf *obj;
		struct ksyms *ksyms;
		int err;
		err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
		if (err)
			return err;
		if (!bpf_is_root())
			return 1;
		libbpf_set_print(libbpf_print_fn);
		obj = biotop_bpf__open();
		if (!obj) {
			warning("Failed to open BPF object\n");
			return 1;
		}
		parse_disk_stat();
		ksyms = ksyms__load();
		if (!ksyms) {
			err = -ENOMEM;
			warning("Failed to load kallsyms\n");
			goto cleanup;
		}
		err = biotop_bpf__load(obj);
		if (err) {
			warning("Failed to load BPF object: %d\n", err);
			goto cleanup;
		}
		err = attach_io_probe(obj, obj->progs.blk_account_io_start,
				      &obj->links.blk_account_io_start,
				      "blk_account_io_start", ksyms);
		if (err)
			goto cleanup;
		err = attach_io_probe(obj, obj->progs.blk_account_io_done,
				      &obj->links.blk_account_io_done,
				      "blk_account_io_done", ksyms);
		if (err)
			goto cleanup;
		err = biotop_bpf__attach(obj);
		if (err) {
			warning("Failed to attach BPF programs: %d\n", err);
			goto cleanup;
		}
		if (signal(SIGINT, sig_handler) == SIG_ERR) {
			warning("Can't set signal handler: %s\n", strerror(errno));
			err =  1;
			goto cleanup;
		}
		while (1) {
			sleep(env.interval);
			if (env.clear_screen) {
				err = system("clear");
				if (err)
					goto cleanup;
			}
			err = print_stat(obj);
			if (err)
				goto cleanup;
			if (exiting || !env.count--)
				goto cleanup;
		}
	cleanup:
		ksyms__free(ksyms);
		free_vector(disks);
		biotop_bpf__destroy(obj);
		return err != 0;
}

int main(int argc, char *argv[])
{
	main_extra();
}
