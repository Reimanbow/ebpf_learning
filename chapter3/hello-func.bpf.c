#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// システムコール番号を取得する
static __attribute((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
	return ctx->args[1];
}

// raw tracepointにアタッチするためのセクション
SEC("raw_tp")
int hello(struct bpf_raw_tracepoint_args *ctx) {
	// システムコール番号を取得
	int opcode = get_opcode(ctx);
	// trace_pipeに出力
	bpf_printk("Syscall: %d", opcode);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";