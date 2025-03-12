#!/usr/bin/python3
from bcc import BPF
import ctypes as ct

'''
1. BCCはBPF_PROG_ARRAYマクロを提供し, BPF_MAP_TYPE_PROG_ARRAY型のMapを定義できる
   このMapはsyscallという名前であり, エントリ数は300である
2. hello()は, ユーザ空間のコードの中で, eBPFプログラムを呼ぶ際に起動する
   Raw TracepointにアタッチされたeBPFプログラムに渡されるコンテキストは, このbpf_raw_tracepoint_args構造体の形になる
3. sys_enterの場合, Raw Tracepointの引数には, どのシステムコールが呼ばれたかを区別するための番号が入っている
4. システムコール番号に対応するサブeBPFプログラムを呼び出すTail Callをしている
   この行はBCCがbpf_tail_call()に書き換えられてからコンパイラに渡す
5. Tail Callが成功した場合, システムコール番号の出力にはたどり着かない
   Mapの中に対応するプログラムがなかった場合のデフォルトのトレース出力をするために使っている
6. hello_execve()はsyscall Mapにロードするためのプログラムで, システムコール番号がexecve()のものであったことを示す
   これはTail Callとして呼び出される. ここでは1行のトレース出力によって, 新しいプログラムが実行されたことを伝える
7. hello_timer()もsyscall Mapにロードされるためのプログラムである. このプログラムはsyscall中の複数のエントリから参照している
8. ignore_opcode()は何もしないTail Callのプログラムである. このプログラムはトレース出力をしてほしくないシステムコールのために使う
'''
program = r"""
BPF_PROG_ARRAY(syscall, 500);

int hello(struct bpf_raw_tracepoint_args *ctx) {
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
# sys_enter Raw Tracepointにアタッチしている
# sys_enterはすべてのシステムコールが呼び出される瞬間に実行される
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

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