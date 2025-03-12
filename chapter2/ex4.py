#!/usr/bin/python3
from bcc import BPF
import ctypes as ct

'''
2.5.4 演習
hello-tail.pyを次のように変更する
- hello()関数の定義を, RAW_TRACEPOINT_PROBE(sys_enter)を利用して置き換える
- b.attach_raw_tracepoint()を利用した明示的なアタッチをPythonコードから削除する
'''
program = r"""
BPF_PROG_ARRAY(syscall, 500);

RAW_TRACEPOINT_PROBE(sys_enter) {
	int opcode = ctx->args[1];
	syscall.call(ctx, opcode);
	bpf_trace_printk("Another syscall: %d", opcode);
	return 0;
}

int hello_execve(void *ctx) {
	bpf_trace_printk("Executing a program");
	return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
	if (ctx->args[1] == 222) {
		bpf_trace_printk("Creating a timer");
	} else if (ctx->args[1] == 226) {
		bpf_trace_printk("Deleting a timer");
	} else {
		bpf_trace_printk("Some other timer operation");
	}
	return 0;
}

int ignore_opcode(void *ctx) {
	return 0;
}
"""

b = BPF(text=program)

# それぞれのTail Callプログラムに対応するファイル記述子を返す
# Tail Callのプログラムは親プログラムと同じBPF.RAW_TRACEPOINTでなければならない
# それぞれのTail Callプログラムは, それぞれ固有の機能を持つ独立したeBPFプログラムである
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_execve", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

# syscall Mapのエントリを作成している
prog_array = b.get_table("syscall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
# タイマ関連のシステムコールが呼び出されたらhello_timer() Tail Callをする
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# 高い頻度で呼び出されるシステムコールは, 何もしないignore_opcode() Tail Callをしている
prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)

# ユーザがプログラムを止めるまで, トレース結果を端末に出力する
b.trace_print()