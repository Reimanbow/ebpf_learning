#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hello-verifier.h"

int c = 1;
char message[12] = "Hello World";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct msg_t);
} my_config SEC(".maps");

SEC("ksyscall/execve")
int kprobe_exec(void *ctx)
{
	struct data_t data = {};
	struct msg_t *p;
	u64 uid;

	data.counter = c;
	c++;

	data.pid = bpf_get_current_pid_tgid() >> 32;
	uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	data.uid = uid;

	p = bpf_map_lookup_elem(&my_config, &uid);
	// p = bpf_amp_lookup_elem(&data, &uid);

	if (p != 0) {
		char a = p->message[0];
		bpf_printk("%d", a);
	}

	if (p != 0) {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
	} else {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
	}

	// if (c <= sizeof(message)) {
	if (c < sizeof(message)) {
		char a = message[c];
		bpf_printk("%c", a);
	}

	// if (c <= sizeof(data.message)) {	
	if (c < sizeof(data.message)) {
		char a = data.message[c];
		bpf_printk("%c", a);
	}

	bpf_get_current_comm(&data.command, sizeof(data.command));
	bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

SEC("xdp")
int xdp_hello(struct xdp_md *ctx) {
	void *data = (void*)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// data_end++;

	// for (int i = 0; i < 10; i++) {
	//	bpf_printk("Looping %d", i);
	// }

	// for (int i = 0; i < c; i++) {
	//	bpf_printk("Looping %d", i);
	// }

	bpf_printk("%x %x", data, data_end);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";