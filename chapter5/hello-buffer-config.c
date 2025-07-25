#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
// 自動生成されたスケルトンヘッダと、ユーザ空間とカーネルの間で共有されるデータ構造
#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
   if (level >= LIBBPF_DEBUG) {
      return 0;
   }

   return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
   struct data_t *m = data;
   printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
   printf("lost event\n");
}

int main() {
   struct hello_buffer_config_bpf *skel;
   struct perf_buffer *pb = NULL;
   int err;

   // libbpfが生成するログメッセージを出力する際に呼び出すコールバック関数を設定する
   libbpf_set_print(libbpf_print_fn);

   // ELFデータ内で定義されたすべてのMapとプログラムを表すskel構造体を作り、カーネルにロードする
   skel = hello_buffer_config_bpf__open_and_load();
   if (!skel) {
      printf("Failed to open BPF object\n");
      return 1;
   }

   // プログラムに適切なイベントにアタッチする
   err = hello_buffer_config_bpf__attach(skel);
   if (err) {
      fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
      hello_buffer_config_bpf__destroy(skel);
      return 1;
   }

   // Perfリングバッファ出力を処理するための構造体を作成する
   pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
   if (!pb) {
      err = -1;
      fprintf(stderr, "Failed to create ring buffer\n");
      hello_buffer_config_bpf__destroy(skel);
      return 1;
   }

   // Perfリングバッファを定期的にポーリングする
   while (true) {
      err = perf_buffer__poll(pb, 100);
      if (err == -EINTR) {
         err = 0;
         break;
      }
      if (err < 0) {
         printf("Error polling perf buffer: %d\n", err);
         break;
      }
   }

   // クリーンアップコード
   perf_buffer__free(pb);
   hello_buffer_config_bpf__destroy(skel);
   return -err;
}