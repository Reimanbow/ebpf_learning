#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello-buffer-config.h"

char message[12] = "Hello World";

// Perfリングバッファoutputを定義
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} output SEC(".maps");

struct user_msg_t {
	char message[12];
};

// キーがユーザID、値がそのユーザに対するメッセージが入った構造体であるuser_msg_tであるハッシュMap
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct user_msg_t);
} my_config SEC(".maps");

// システムコールの引数に名前でアクセスしやすくするBPF_KPROBE_SYSCALLマクロ
// execve()の場合、最初の引数は実行されるプログラムのパス名を示す。eBPFプログラムの名前はhelloである
SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
	struct data_t data = {};
	struct user_msg_t *p;

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));
	// マクロによってプログラムのパス名にアクセスできるようになったので、それをPerfリングバッファの出力に使われるデータ領域に保存
	bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

	// bpf_map_lookup_elem()はキーを指定してMapの値を得るBPFヘルパ関数
	p = bpf_map_lookup_elem(&my_config, &data.uid);
	if (p != 0) {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
	} else {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
	}

	// ヘルパ関数bpf_perf_event_output()を直接使う
	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU,
						  &data, sizeof(data));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";