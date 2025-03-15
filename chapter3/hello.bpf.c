#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// プログラムが動作するたびに値が増えるカウンタ
int counter = 0;

// xdpというセクションを定義する
SEC("xdp")
/**
 * eBPFプログラムの実体
 * eBPFでは, プログラム名は関数名と同じになるため, このプログラム名はhelloである
 * この関数はヘルパ関数bpf_printkを使ってメッセージを出力し, 
 * グローバル変数counterを増やし, XDP_PASSという値を返す
 * これによって, このパケットは通常通り取り扱うべしとカーネルに伝える
 */
int hello(void *ctx) {
	bpf_printk("Hello World %d", counter);
	counter++;
	return XDP_PASS;
}

/**
 * ライセンス文字列を定義する別のSECマクロ
 * BPFプログラムにとって必須事項である
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";