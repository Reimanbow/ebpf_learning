#!/usr/bin/python3
from bcc import BPF

'''
eBPFプログラム
1. メッセージをユーザ空間に渡すMapを作るためのBPF_PERF_OUTPUTマクロを提供している. Mapの名前はoutput
2. hello()が起動することに書き込むデータの型であるdata_t型の定義
   プロセスID, ユーザID, 現在実行中のコマンド名, テキストメッセージを持つフィールドを持つ
3. dataは送信する予定のデータを保持するローカル変数で, messageは「Hello World」の文字列を保持する
4. bpf_get_current_pid_tgid()は, このeBPFプログラムをトリガーしたプロセスIDを取得するヘルパ関数
   この関数は64ビットの値を返し, 上位32ビットがプロセスIDを, 下位32ビットがスレッドIDを示す
5. bpf_get_current_uid_git()はユーザIDを取得するためのヘルパ関数
6. bpf_get_current_comm()は, execve()システムコールを呼び出したプロセスを立ち上げた実行ファイル(コマンド)の名前を取得するヘルパ関数
   この値はプロセスやユーザIDのような整数ではなく, 文字列である. 文字列を=を使うことはできないのポインタを渡す形式となっている
7. ここで書き込むメッセージは常に"Hello World"である. bpf_probe_read_kernel()はこの文字列をdata変数のmessageにコピーする
8. output.perf_submit()によって, 変数のデータをMapに挿入する
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
	char message[12] = "Hello World";
	
	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));
	bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

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