#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <err.h>
#include <stdlib.h>
#include "linux/kvm.h"

#define u64 unsigned long
#define u32 unsigned int
#define u16 unsigned short
#define u8 unsigned char

void setup(void)
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

/* For KVM_EXIT_INTERNAL_ERROR */
/* Emulate instruction failed. */

char internal_errors[][0x100] =
{
        "",
        "KVM_INTERNAL_ERROR_EMULATION",
        "KVM_INTERNAL_ERROR_SIMUL_EX",
        "KVM_INTERNAL_ERROR_DELIVERY_EV",
        "KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON",
        0x0
};

#define KVM_INTERNAL_ERROR_EMULATION 1
/* Encounter unexpected simultaneous exceptions. */
#define KVM_INTERNAL_ERROR_SIMUL_EX 2
/* Encounter unexpected vm-exit due to delivery event. */
#define KVM_INTERNAL_ERROR_DELIVERY_EV 3
/* Encounter unexpected vm-exit reason */
#define KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON 4

int main(void)
{
    setup();
    int fd = open("./bios.bin", O_RDONLY);
    /* int fd = open("./test", O_RDONLY); */
    int len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    void *code_buf = malloc(len);
    read(fd, code_buf, len);


    int kvm, vmfd, vcpufd, ret;
    uint8_t *mem;
    struct kvm_sregs sregs;
    size_t mmap_size;
    struct kvm_run *run;

    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm == -1)
        err(1, "/dev/kvm");

    /* Make sure we have the stable version of the API */
    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
        err(1, "KVM_GET_API_VERSION");
    if (ret != 12)
        errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

    vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
    if (vmfd == -1)
        err(1, "KVM_CREATE_VM");

    /* Allocate one aligned page of guest memory to hold the code. */
    mem = mmap(NULL, 0x100000000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    /* memset(mem, 0, 0x100000000); //pre touch all pages for speeeed!!! could do this per page and not byte */

    if (!mem)
        err(1, "allocating guest memory");
    /* memcpy(mem + 0xf0000, code_buf + 0x30000, 0x10000); */
    memcpy(mem + 0xf0000, code_buf, len);

    /* Map it to the second page frame (to avoid the real-mode IDT at 0). */
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0x0,
        .memory_size = 0x100000000,
        .userspace_addr = (uint64_t)mem,
    };
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
    if (vcpufd == -1)
        err(1, "KVM_CREATE_VCPU");

    /* Map the shared kvm_run structure and following data. */
    ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    mmap_size = ret;
    if (mmap_size < sizeof(*run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (!run)
        err(1, "mmap vcpu");

    /* Initialize CS to point at 0, via a read-modify-write of sregs. */
    memset(&sregs, 0, sizeof(sregs));
    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
    sregs.cs.base = 0xf0000;
    sregs.cs.selector = 0xf000;
    sregs.cs.limit = 0xffff;
    ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_SET_SREGS");

    /* Initialize registers: instruction pointer for our code, addends, and
     * initial flags required by x86 architecture. */
    struct kvm_regs regs = {
        .rip = 0xfff0,
        /* .rip = 0x6, */
        .rax = 2,
        .rbx = 2,
        .rdx = 0x00060fb1,
        .rflags = 0x2,
    };
    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");

    /* Repeatedly run code and handle VM exits. */
    while (1) {
        ret = ioctl(vcpufd, KVM_RUN, NULL);
        ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
        ret = ioctl(vcpufd, KVM_GET_REGS, &regs);
        if (ret == -1)
            dprintf(2, "KVM_RUN\n");
        switch (run->exit_reason) {
        case KVM_EXIT_HLT:
            puts("KVM_EXIT_HLT");
            goto quit;
        case KVM_EXIT_IO:
            if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1){
                uint64_t off = run->io.data_offset;
                char *ptr = ((char *)run) + off;
                char c = *ptr;
                putchar(c);
                break;
            } else if (run->io.direction == KVM_EXIT_IO_IN && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1){
                uint64_t off = run->io.data_offset;
                char *ptr = ((char *)run) + off;
                char c = getchar();
                *ptr = c;
                break;
            } else if (run->io.port == 0x3fd) {
                uint64_t off = run->io.data_offset;
                char *ptr = ((char *)run) + off;
                *ptr = '\xff';
                break;
            }
            else if ((run->io.port & 0xff20) == 0x20 || (run->io.port & 0xffa0) == 0xa0 || (run->io.port == 0x80)) {
                /* dprintf(2, "IRQ controller int.\n"); */
                break;
            } else {
                /* printf("io->port: 0x%04hx\n", run->io.port); */
                /* printf("io->dir: 0x%02hx\n", run->io.direction); */
                break;
            }
            break;
        case KVM_EXIT_FAIL_ENTRY:
            dprintf(2, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx\n",
                 (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
            goto quit;
        case KVM_EXIT_INTERNAL_ERROR:
            dprintf(2, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x\n", run->internal.suberror);
            goto quit;
        default:
            dprintf(2, "exit_reason = 0x%x\n", run->exit_reason);
            goto quit;
        }
    }

quit:
    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    ret = ioctl(vcpufd, KVM_GET_REGS, &regs);
    printf("cr0:         0x%016llX\n", sregs.cr0);
    printf("cr2:         0x%016llX\n", sregs.cr2);
    printf("cr3:         0x%016llX\n", sregs.cr3);
    printf("cr4:         0x%016llX\n", sregs.cr4);
    printf("cs base:     0x%016llX\n", sregs.cs.base);
    printf("cs limt:     0x%016llX\n", sregs.cs.limit);
    printf("cs selector: 0x%016llX\n", sregs.cs.selector);
    printf("gdt base:    0x%016llX\n", sregs.gdt.base);
    printf("gdt limit:   0x%016llX\n", sregs.gdt.limit);
    printf("efer:        0x%016llX\n", sregs.efer);
    printf("rip:         0x%016llX\n", regs.rip);
    printf("rax:         0x%016llX\n", regs.rax);
    printf("rbx:         0x%016llX\n", regs.rbx);
    printf("rcx:         0x%016llX\n", regs.rcx);
    printf("rdx:         0x%016llX\n", regs.rdx);

    puts("");
    printf("io->port: 0x%04hx\n", run->io.port);
    printf("io->dir: 0x%02hx\n", run->io.direction);
    exit(0);
}
