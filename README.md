[简体中文](README.md) | [English](README.en.md)

# PilotGo-plugin-observation

#### 介绍
PilotGo observation plugin 基于 eBPF 技术增强系统可观测性，汇集了一系列以 libbpf 实现的性能分析与 tracing 工具（如 execsnoop、biosnoop、tcptop 等），用于观测进程调度、文件系统、块设备、网络等内核行为。

#### 软件架构
项目主要由以下几部分组成：

- `bpftool/`：bpftool 源码，用于加载/调试 BPF 程序、生成 BTF 与骨架代码。
- `libbpf/`：libbpf 用户态库源码，是各工具的 BPF 加载基础设施。
- `src/`：各观测工具，每个子目录为一个工具，通常包含三个文件：
  - `<tool>.bpf.c`：内核态 BPF 程序（挂载 tracepoint/kprobe/uprobe 等）。
  - `<tool>.c`：用户态程序（解析参数、加载 BPF、读取事件并输出）。
  - `<tool>.h`：内核态与用户态共享的数据结构定义。
- `src/include/`：公共头文件（maps、commons、trace/btf helpers 等）。
- `vmlinux/`：各架构（x86、arm64、loongarch）预生成的 `vmlinux.h`，供 CO-RE 使用。

#### 使用说明
每个工具独立编译运行，均需 root 权限，并依赖内核开启 BPF/BTF 支持。以 execsnoop 为例：

- `execsnoop`：追踪所有 exec() 系统调用。
- `execsnoop -x`：包含失败的 exec()。
- `execsnoop -T`：输出中包含时间（HH:MM:SS）。
- `execsnoop -u 1000`：仅追踪指定 UID。

其余工具的可用参数可通过 `<tool> -h` 查看。

#### 参与贡献

1.  Fork 本仓库
2.  新建特性分支（`git checkout -b feat-xxx`）
3.  提交改动（`git commit -m "..."`）
4.  新建 Pull Request / Merge Request
