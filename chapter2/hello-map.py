#!/usr/bin/python3
from bcc import BPF
from time import sleep

'''
eBPFプログラム
1. BPF_HASH()はハッシュテーブルMapを定義するためのBCCのマクロである
2. bpf_get_current_uid_gid()はこのkprobeイベントをトリガーしたプロセスを所有しているユーザIDを取得する
   返り値は64ビットだが, 上位32ビットがgid, 下位32ビットがuidである
3. ハッシュテーブルに, 対応するユーザIDのエントリがあるかを確認している. 存在する場合はハッシュテーブル内の対応する値へのポインタを返す
4. ユーザIDに対応するエントリがあった場合, counterという変数にハッシュテーブルの現在の値(pポインタが示す値)を設定する
   ユーザIDに対応するエントリがなかった場合は, ポインタは0となり, カウンタの値も0のままである
5. カウンタの値を1増やす
6. 新しいカウンタの値でハッシュテーブル内のユーザIDのエントリを更新する
'''
program = r"""
BPF_HASH(counter_table);

int hello(void *ctx) {
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
# execve()に相当するカーネル関数を見つける
syscall = b.get_syscall_fnname("execve")
# kprobeを用いて, execve()が呼び出されたときにhello()を実行する
b.attach_kprobe(event=syscall, fn_name="hello")

# eBPFのプログラムはカーネルにロードされてイベントにアタッチされる

# 2秒ごとに採取した情報を出力する
while True:
	sleep(2)
	s = ""
	# テーブルにあるすべてのキーと値を出力している
	for k, v in b["counter_table"].items():
		s += f"ID {k.value}: {v.value}\t"
	print(s)