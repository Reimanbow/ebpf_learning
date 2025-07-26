#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello.h"

const char kprobe_sys_msg[16] = "sys_execve";
const char kprobe_msg[16] = "do_execve";
const char fentry_msg[16] = "fentry_execve";
const char tp_msg[16] = "tp_execve";
const char tp_btf_exec_msg[16] = "tp_btf_exec";
const char raw_tp_exec_msg[16] = "raw_tp_exec";
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct msg_t);
} my_config SEC(".maps");

// システムコールレベルでの監視. システムコールインタフェースでexecveを直接フック
SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(kprobe_sys_execve, const char *pathname)
{
	struct data_t data = {};

	bpf_probe_read_kernel(&data.message, sizeof(data.message), kprobe_sys_msg);
	bpf_printk("%s: pathname: %s", kprobe_sys_msg, pathname);

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&data.command, sizeof(data.command));
	bpf_probe_read_user(&data.path, sizeof(data.path), pathname);

	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

#ifndef __TARGET_ARCH_arm64
// カーネル関数へのkprobe(カーネル内部のdo_execve関数にプローブを設置)
SEC("kprobe/do_execve")
int BPF_KPROBE(kprobe_do_execve, struct filename *filename) {
	struct data_t data = {};

	bpf_probe_read_kernel(&data.message, sizeof(data.message), kprobe_msg);

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));
	const char *name = BPF_CORE_READ(filename, name);
	bpf_probe_read_kernel(&data.path, sizeof(data.path), name);

	bpf_printk("%s: filename->name: %s", kprobe_msg, name);

	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}
#endif

#ifndef __TARGET_ARCH_arm64
// 関数エントリでの監視(より効率的なfentryフックを使用)
SEC("fentry/do_execve")
int BPF_PROG(fentry_execve, struct filename *filename) {
	struct data_t data = {};

	bpf_probe_read_kernel(&data.message, sizeof(data.message), fentry_msg);

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));
	const char *name = BPF_CORE_READ(filename, name);
	bpf_probe_read_kernel(&data.path, sizeof(data.path), name);

	bpf_printk("%s: filename->name: %s", fentry_msg, name);

	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}
#endif

struct my_syscalls_enter_execve {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	long syscall_nr;
	void *filename_ptr;
	long argv_ptr;
	long envp_ptr;
};

// トレースポイント. 静的に定義されたトレースポイントを使用. システムコールエントリポイントで監視
SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct my_syscalls_enter_execve *ctx) {
	struct data_t data = {};

	bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg);
	bpf_printk("%s: ctx->filename_ptr: %s", tp_msg, ctx->filename_ptr);

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));
	bpf_probe_read_user(&data.path, sizeof(data.path), ctx->filename_ptr);

	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

// BTFトレースポイント. BTF情報を使用したトレースポイント. スケジューラレベルでプロセス実行を監視
SEC("tp_btf/sched_process_exec")
int tp_bpf_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct data_t data = {};

	bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_btf_exec_msg);

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

// Rawトレースポイント. 最も低レベルなトレースポイント
SEC("raw_tp/sched_process_exec")
int raw_tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
	struct data_t data = {};

	bpf_probe_read_kernel(&data.message, sizeof(data.message), raw_tp_exec_msg);

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";