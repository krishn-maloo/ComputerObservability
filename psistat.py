#!/usr/bin/env python3
from bcc import BPF
from time import sleep
import psutil

# Define the eBPF program to capture memory PSI statistics
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/psi.h>

BPF_HASH(psi_mem, u64, struct psi_memstall);

int trace_psi_mem(struct pt_regs *ctx) {
    struct psi_memstall *mem_data;
    u64 id = bpf_get_current_pid_tgid();
    mem_data = psi_mem.lookup(&id);
    if (mem_data == 0) {
        struct psi_memstall mem = {};
        psi_mem.update(&id, &mem);
    }
    bpf_probe_read(&mem_data->total, sizeof(mem_data->total), &ctx->ax);
    bpf_probe_read(&mem_data->some, sizeof(mem_data->some), &ctx->di);
    bpf_probe_read(&mem_data->full, sizeof(mem_data->full), &ctx->si);
    return 0;
}
"""

# Load the memory PSI eBPF program
b = BPF(text=bpf_text)
b.attach_psi_mem("psi_mem")

# Define a function to read memory PSI statistics
def read_mem_psi():
    stats = {}
    for k, v in b.get_table("psi_mem").items():
        stats[k.value] = {
            "total": v.total,
            "some": v.some,
            "full": v.full,
        }
    return stats

# Main loop to collect memory PSI statistics
while True:
    mem_psi = read_mem_psi()
    for pid, psi_data in mem_psi.items():
        print(f"Memory PSI for PID {pid}: {psi_data}")
    sleep(1)

# Note: This is an example for memory PSI statistics. You can create a similar
# eBPF program and functions to capture CPU PSI statistics as well.

