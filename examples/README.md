# eBPF Examples

- Kprobe - Attach a program to the entry or exit of an arbitrary kernel symbol (function).
  - [kprobe](kprobe/) - Kprobe using bpf2go.
  - [kprobepin](kprobepin/) - Reuse a pinned map for the kprobe example. It assumes the BPF FS is mounted at `/sys/fs/bpf`.
  - [kprobe_percpu](kprobe_percpu/) - Use a `BPF_MAP_TYPE_PERCPU_ARRAY` map.
  - [ringbuffer](ringbuffer/) - Use a `BPF_MAP_TYPE_RINGBUF` map.
- Uprobe - Attach a program to the entry or exit of an arbitrary userspace binary symbol (function).
  - [uretprobe](uretprobe/) - Uretprobe using bpf2go.
- Tracepoint - Attach a program to predetermined kernel tracepoints.
  - [tracepoint_in_c](tracepoint_in_c/) - Tracepoint using bpf2go.
  - [tracepoint_in_go](tracepoint_in_go/) - Tracepoint using the `ebpf.NewProgram` API and Go eBPF assembler.
- Cgroup - Attach a program to control groups (cgroups).
  - [cgroup_skb](cgroup_skb/) - Count packets egressing the current cgroup.
- Fentry - Attach a program to the entrypoint of a kernel function.
  Like kprobes, but with better performance and usability, for kernels 5.5 and later.
  - [tcp_connect](fentry/) - Trace outgoing IPv4 TCP connections.
  - [tcp_close](tcprtt/) - Log RTT of IPv4 TCP connections using eBPF CO-RE helpers.
- XDP - Attach a program to a network interface to process incoming packets.
  - [xdp](xdp/) - Print packet counts by IPv4 source address.
- BPF Compiler Collection (BCC)
  - [execsnoop](execsnoop/) - Trace new processes via exec() syscalls, and print the parent process name and other details.
  - [tcpconnect](tcpconnect/) - Trace TCP active connections.
  - [tcpconnlat](tcpconnlat/) - Trace TCP active connection latency (connect).
  - [tcplife](tcplife/) - Trace the lifespan of TCP sessions showing their duration, address details, throughput, the responsible process ID and name.
- Add your use case(s) here!

## How to generate vmlinux.h

```sh
sudo apt-get install linux-tools-common linux-tools-6.2.0-35-generic
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./headers/vmlinux.h
```

## How to run

```bash
cd ebpf/examples/
go run -exec sudo [./kprobe, ./uretprobe, ./ringbuffer, ...]
```

## How to recompile

The examples are built via `go generate` invoked by the Makefile in the project root.

```
make -C ../
```
