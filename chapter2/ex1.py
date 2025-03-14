#!/usr/bin/python3
from bcc import BPF

'''
2.5.1 演習
PIDが奇数か偶数かによって別々のメッセージを表示する
'''
program = r"""
BPF_PERF_OUTPUT(output);

struct data_t {
	int pid;
	int uid;
	char command[16];
	char message[12];
};

int hello(void *ctx) {
	struct data_t data = {};
	char odd_message[12] = "pid is odd";
	char even_message[12] = "pid is even";
	
	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));

	if (data.pid % 2 == 0) {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), odd_message);
	} else {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), even_message);
	}
	
	output.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# eBPFのプログラムはカーネルにロードされてイベントにアタッチされる

# データを画面に出力するためのコールバック関数
def print_event(cpu, data, size):
	# b["output"]でMapを参照し, b["output"].event()でデータを利用できる
	data = b["output"].event(data)
	print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

# Perfリングバッファを開く. データがバッファから読み出されたときのコールバックとしてprint_eventを使う
b["output"].open_perf_buffer(print_event)
# Perfリングバッファをポーリングする. 取り出していないデータがあれば, 取り出してprint_eventを呼び出す
while True:
	b.perf_buffer_poll()