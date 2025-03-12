#!/usr/bin/python3
from bcc import BPF
from time import sleep

'''
2.5.5 演習
ハッシュテーブルのキーが特定のシステムコールを意味するようにする
'''
program = r"""
BPF_HASH(counter_table);

int hello(struct bpf_raw_tracepoint_args *ctx) {
	u64 syscall_num = ctx->args[1];
	u64 counter = 0;
	u64 *p;

	p = counter_table.lookup(&syscall_num);
	if (p != 0) {
		counter = *p;
	}

	counter++;
	counter_table.update(&syscall_num, &counter);
	return 0;	
}
"""

# C言語コードをコンパイルする
b = BPF(text=program)
# kprobeを用いて, execve()が呼び出されたときにhello()を実行する
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# eBPFのプログラムはカーネルにロードされてイベントにアタッチされる

# 2秒ごとに採取した情報を出力する
while True:
	sleep(2)
	s = ""
	# テーブルにあるすべてのキーと値を出力している
	for k, v in b["counter_table"].items():
		s += f"ID {k.value}: {v.value}\t"
	print(s)