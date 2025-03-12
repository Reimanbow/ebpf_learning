#!/usr/bin/python3
from bcc import BPF
from time import sleep

'''
2.5.2 演習
2つ以上のシステムコールからeBPFのコードがトリガーされるようにする
'''
program = r"""
BPF_HASH(counter_table);

int hello_execve(void *ctx) {
	u64 uid;
	u64 counter = 0;
	u64 *p;

	uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	p = counter_table.lookup(&uid);
	if (p != 0) {
		counter = *p;
	}
	counter++;
	counter_table.update(&uid, &counter);
	return 0;
}

int hello_openat(void *ctx) {
	u64 uid;
	u64 counter = 0;
	u64 *p;

	uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	p = counter_table.lookup(&uid);
	if (p != 0) {
		counter = *p;
	}
	counter++;
	counter_table.update(&uid, &counter);
	return 0;
}

int hello_read(void *ctx) {
	u64 uid;
	u64 counter = 0;
	u64 *p;

	uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	p = counter_table.lookup(&uid);
	if (p != 0) {
		counter = *p;
	}
	counter++;
	counter_table.update(&uid, &counter);
	return 0;
}
"""

# C言語コードをコンパイルする
b = BPF(text=program)

# システムコールとeBPF関数の対応を定義
syscall_map = {
	"execve": "hello_execve",
	"openat": "hello_openat",
	"read": "hello_read"
}

# 各システムコールに `hello` をアタッチ
for syscall, fn_name in syscall_map.items():
    fnname = b.get_syscall_fnname(syscall)
    b.attach_kprobe(event=fnname, fn_name=fn_name)

# eBPFのプログラムはカーネルにロードされてイベントにアタッチされる

# 2秒ごとに採取した情報を出力する
while True:
	sleep(2)
	s = ""
	# テーブルにあるすべてのキーと値を出力している
	for k, v in b["counter_table"].items():
		s += f"ID {k.value}: {v.value}\t"
	print(s)