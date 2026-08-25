#include "core/firewall_ctx.h"
#include <signal.h>
#include <stdio.h>

static struct firewall_ctx g_fw;

static void sig_handler(int sig) {
  if (sig == SIGHUP) {
    firewall_ctx_reload(&g_fw);
  } else {
    g_fw.running = 0;
  }
}

int main(int argc, char **argv) {
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  signal(SIGHUP, sig_handler);

  if (firewall_ctx_init(&g_fw, argc, argv) < 0) {
    return 1;
  }

  int rc = firewall_ctx_run(&g_fw);

  firewall_ctx_stop(&g_fw);
  return rc;
}
