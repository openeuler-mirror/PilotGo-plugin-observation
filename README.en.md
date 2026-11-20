# PilotGo-plugin-observation

#### Description
PilotGo observation plugin uses eBPF to enhance system observability. It ships a set of libbpf-based performance analysis and tracing tools (such as execsnoop, biosnoop, tcptop) for observing process scheduling, filesystem, block device and network behavior in the kernel.

#### Software Architecture
- `bpftool/`: bpftool sources used to load/debug BPF programs and generate BTF and skeletons.
- `libbpf/`: the libbpf user-space library that provides BPF loading infrastructure.
- `src/`: the observation tools, one directory per tool, typically containing:
  - `<tool>.bpf.c`: kernel-space BPF program (attached to tracepoints/kprobes/uprobes).
  - `<tool>.c`: user-space program (argument parsing, BPF loading, event reading and output).
  - `<tool>.h`: data structures shared between kernel and user space.
- `src/include/`: common headers (maps, commons, trace/btf helpers, etc.).
- `vmlinux/`: pre-generated `vmlinux.h` for x86/arm64/loongarch used by CO-RE.

#### Instructions
Each tool is built and run independently, requires root privileges, and relies on kernel BPF/BTF support. For example:

- `execsnoop`: trace all exec() syscalls.
- `execsnoop -x`: include failed exec() calls.
- `execsnoop -T`: include time (HH:MM:SS) in output.
- `execsnoop -u 1000`: only trace the given UID.

Run `<tool> -h` to see all options for other tools.

#### Contribution

1.  Fork the repository
2.  Create a feature branch (`git checkout -b feat-xxx`)
3.  Commit your changes (`git commit -m "..."`)
4.  Create a Pull Request / Merge Request
