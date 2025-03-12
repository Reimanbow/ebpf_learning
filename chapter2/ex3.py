#!/usr/bin/python3
from bcc import BPF
from time import sleep

'''
2.5.3 演習
UIDごとに呼び出されるすべてのシステムコールの呼び出しの合計を表示するように変更する
その際, 同じsys_enter Raw Tracepointにアタッチする
'''
program = r"""
BPF_HASH(counter_table);

int hello(struct bpf_raw_tracepoint_args *ctx) {
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

b = BPF(text=program)
# sys_enter Raw Tracepointにアタッチしている
# sys_enterはすべてのシステムコールが呼び出される瞬間に実行される
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# ユーザがプログラムを止めるまで, トレース結果を端末に出力する
# 2秒ごとに採取した情報を出力する
while True:
	sleep(2)
	s = ""
	# テーブルにあるすべてのキーと値を出力している
	for k, v in b["counter_table"].items():
		s += f"ID {k.value}: {v.value}\t"
	print(s)