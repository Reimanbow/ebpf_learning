#!/usr/bin/python3
from bcc import BPF

# カーネルで実行されるeBPFプログラム
# C言語で書かれる
# bpf_trace_printk()を使いメッセージを書き込む
program = r"""
int hello(void *ctx) {
	bpf_trace_printk("Hello World!!");
	return 0;
}
"""

# BCCフレームワークにC言語のプログラムをコンパイルさせる
b = BPF(text=program)
# execve(2)が呼び出されたら, eBPFプログラムが実行される
syscall = b.get_syscall_fnname("execve")
# kprobeを用いてhello関数をexecve(2)呼び出し時に実行させる
b.attach_kprobe(event=syscall, fn_name="hello")

# eBPFのプログラムはカーネルにロードされてイベントにアタッチされる

# カーネルに出力されるトレース結果を読み出して画面上に表示する
b.trace_print()