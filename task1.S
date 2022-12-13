[bits 16]
org 0x0                         ; actually this is at 0xf0000 as the code segement register is 0xf000 upon boot

    ;; nice macros
%imacro save16regs 0            ; helper macro for push all regs
    push bp
    push ax
    push bx
    push cx
    push dx
    push di
    push si
    push bp
%endmacro

%imacro restore16regs 0         ; yee restore them
    pop bp
    pop si
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
    pop bp
%endmacro

;; end macros

ivt_spacing equ 0x8
ivt:                            ; macro loop for inserting ivt entries
%assign i 0
%rep    256
    dw 0x1000 + i*ivt_spacing          ; .data segment cannot be bigger than 0x1000
    dw 0xf000
%assign i i+1
%endrep

_ivt:
    dd 0x3ff                    ; limit idt
    dd 0x0                      ; base idt

normal_stack:
    dw 0xa000
ivt_stack:
    dw 0xb000
retval64:
    dw 0x000

align 0x20
gdtr:                           ;gdt for 64 bit
dw 8 * 4 - 1                    ;4 is number of segments
dd gdt

gdt:
dq 0x0000000000000000 ; null segment (x86 spec needs it)
dq 0x00Af9A000000ffff ; 64 bit code segment
dq 0x001f9A000000ffff ; here we clear the 64bit flag and 32bit flag and set a limit
dq 0x00cf93000000ffff ; stack

times 0x500-($-$$) db 0         ;getting fixed addr for bits64 function

[bits 64]
bits64:                         ;crazy hack puting code in data but we need
                                ;small snippet in lower address space as jmp
                                ;only takes a 16bit val so we cant set rip
                                ;directly to 0xfxxxx
    and rdi, 0x000000000000ffff
    mov ax, 0x18
    mov ss, ax
    mov rsp, 0xfff000
    add rdi, 0xf0000
    mov rax, rdi
    mov rdi, rsi
    call rax
    jmp (exit + 0xf0000)


[bits 16]
exit_trampoline:
    mov eax, cr0
    and eax, 0xfffffffe         ; disable protected mode
    mov cr0, eax
    jmp 0x0:page_disable

page_disable:
    mov eax, cr0
    and eax, 0x7fffffff         ; disable paging
    mov cr0, eax
    jmp 0xf000:exit_restore_regs

exit_restore_regs:
    mov ax, 0x0
    mov ss, ax
    mov sp, [normal_stack]        ; save old rsp
    restore16regs
    mov ax, 0xf000
    sti                           ; enable interupts again
    jmp 0xf000:retback

retback:
    mov ax, [retval64]
    ret

prompt:
    db '> ', 0

align 0x1000                      ; actually data segment must be exactly 0x1000
data_segment_end:                 ; code segment starts here and is mapped to code selector 0xf000
                                  ; code go brrr:
chall_in_out:

    ;;  ivt jump talbe here
%assign i 0
%rep    0x14
    cli                         ; no interupts while interupting
    mov ax, i
    jmp int_handler
    align ivt_spacing            ; should be enoguh for a jump table
%assign i i+1
%endrep

jmp instruction_int_14_handler     ; special handler for serial communication
align ivt_spacing

%assign i 0
%rep    (0x100 - 0x15)
    cli                         ; no interupts while interupting
    mov ax, (i + 0x15)
    jmp hw_int_handler
    align ivt_spacing
%assign i i+1
%endrep

align 0x0800                    ; end ivt jump talbe

int_handler:
mov bx, ax
mov eax, 0xdea0
hlt

hw_int_handler:
mov bx, ax
mov eax, 0xdea1
hlt

    ;; boiler plate done for fault detection ivt
    ;; probably gonna need it for when i divide by 0 or some stupid shit later

io_wait:
    push dx
    push ax
    mov dx, 0x80
    mov ax, 0x0
    out dx, al
    pop ax
    pop dx
    ret

PIC1 equ 0x20
PIC2 equ 0xa0
PIC1_COMMAND equ PIC1
PIC2_COMMAND equ PIC2
PIC1_DATA equ (PIC1+1)
PIC2_DATA equ (PIC2+1)

ICW1_ICW4 equ 0x01
ICW1_SINGLE equ 0x2
ICW1_INTERVAL4 equ 0x4
ICW1_LEVEL equ 0x8
ICW1_INIT equ 0x10

ICW4_8086 equ 0x1
ICW4_AUTO equ 0x2
ICW4_BUF_SLAVE equ 0x8
ICW4_BUF_MASTER equ 0xc
ICW4_SFNM equ 0xc

setup_interupt_controller:        ; init pic 8259a
    push ax

    xor ax, ax
    in al, PIC1_DATA                ; save masks
    push ax

    xor ax, ax
    in al, PIC2_DATA
    push ax

    mov dx, PIC1_COMMAND                ; starts the initialization sequence (in cascade mode)
    mov ax, (ICW1_INIT | ICW1_ICW4)
    out dx, al
    call io_wait

    mov dx, PIC2_COMMAND
    mov ax, (ICW1_INIT | ICW1_ICW4)
    out dx, al
    call io_wait


    mov dx, PIC1_DATA
    mov ax, 0x60                        ; Master PIC vector offset
    out dx, al
    call io_wait

    mov dx, PIC2_DATA
    mov ax, 0x68                        ; Slave PIC vector offset
    out dx, al
    call io_wait


    mov dx, PIC1_DATA
    mov ax, 0x4                         ; Tell master PIC that there is a slave PIC at IRQ2
    out dx, al
    call io_wait

    mov dx, PIC1_DATA
    mov ax, 0x2                         ; tell Slave PIC its cascade identity
    out dx, al
    call io_wait


    mov dx, PIC1_DATA
    mov ax, ICW4_8086
    out dx, al
    call io_wait

    mov dx, PIC1_DATA
    mov ax, ICW4_8086
    out dx, al
    call io_wait

    mov dx, PIC2_DATA                   ; Restore mask inorder they were pushed
    pop ax
    out dx, al
    call io_wait

    mov dx, PIC1_DATA
    pop ax
    out dx, al
    call io_wait
    pop dx
    ret

set_irq_bit_mask_line:
    push dx
    push bx
    push cx
    mov bx, PIC1_DATA
    mov dx, PIC2_DATA
    cmp di, 0x8
    jae set_irq_move_skip
    mov dx, bx
set_irq_move_skip:
    and di, 0x0f
    mov cx, di
    in al, dx
    mov si, 1
    shl si, cl
    or ax, si
    out dx, al
    pop cx
    pop bx
    pop dx
    ret

clea_irq_bit_mask_line:
    push dx
    push bx
    push cx
    mov bx, PIC1_DATA
    mov dx, PIC2_DATA
    cmp di, 0x8
    jae clear_irq_move_skip
    mov dx, bx
clear_irq_move_skip:
    and di, 0x0f
    mov cx, di
    in al, dx
    mov si, 1
    shl si, cl
    xor si, 0xffff
    and ax, si
    out dx, al
    pop cx
    pop bx
    pop dx
    ret

instruction_int_14_handler:
    cld
    mov [normal_stack], sp
    mov sp, [ivt_stack]
    push di
    push si
    push dx
    mov dx, di
    mov di, 0x14
    mov si, ax
    and si, 0xff00
    shr si, 8
    call instruction_handler
inst_exit:
    pop dx
    pop si
    pop di
    mov sp, [normal_stack]
    iret                        ; iret will take care of restoring interuptflag and direction flag?

instruction_handler:
    cmp di, 0x14
    jne inst_err
    mov di, si
    mov si, dx
    call serial_handle
    ret
inst_err:
    mov eax, 0xdea2
    hlt

UART equ 0x3f8

serial_handle:
    cmp di, 0x0
    je serial_init
    cmp di, 0x2
    je serial_read
    cmp di, 0x3
    je serial_status
    cmp di, 0x1
    mov di, si
    je serial_write
    ret

serial_init:
    push dx
    mov ax, 0x00
    mov dx ,(UART + 1)
    out dx, al                  ; Disable all interrupts
    mov ax, 0x80
    mov dx ,(UART + 3)
    out dx, al                  ; Enable DLAB (set baud rate divisor)
    mov ax, 0x01
    mov dx ,(UART + 0)
    out dx, al                  ; Set divisor to 1 (lo byte) 115200/1 baud
    mov ax, 0x00
    mov dx ,(UART + 1)
    out dx, al                  ; hi byte devisor
    mov ax, 0x03
    mov dx ,(UART + 3)
    out dx, al                  ; 8 bits, no parity, one stop bit

    xor ax, ax
    mov dx ,(UART + 4)
    out dx, al                  ; Serial is not faulty 🤞 (we could do loop back test but nah)
                                ; Put it in normal operation mode
    pop dx
    ret

serial_check_fail:
    mov eax, 0xdea3
    hlt

serial_write:
    push dx
    mov ax, di
    mov dx ,(UART + 0)
    out dx, al
    pop dx
    ret

serial_read:
    push dx
    mov ax, 0x0
    mov dx ,(UART + 0)
    in al, dx
    pop dx
    ret

serial_status:
    push dx
    mov ax, 0x0
    mov dx ,(UART + 5)
    in al, dx
    pop dx
    ret

align 0x1000                       ; io code ends here

boot:
    cli                             ; disable interupt, nothing works doh.
    mov ax, 0xf000
    mov ds, ax                      ; setup data segment
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov es, ax

    mov eax, 0x0                    ; copy everything to writeable space
    mov fs,  ax
    mov bx, 0x0
    mov cx, data_segment_end
copyloop:
        mov al, [ds:bx]
        mov [fs:bx], al
        inc bx
        dec cx
        test cx, cx
        jnz copyloop

    mov ax, 0x0                     ; setup new segments
    mov ds, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov es, ax
    ;; mov cs, ax                   ; we don't move cs as we should still read code from read only
    mov sp, [ds:normal_stack]        ; no recursion it could blow up the ivt

    lidt [_ivt]                     ; setup ivt
    mov ax, 0xf000
    mov fs, ax                      ; done setting up ivt
    mov eax, 0x10
    mov cr0, eax

    call setup_interupt_controller
    mov di, 0x0
    call set_irq_bit_mask_line          ; disable programable timer
    sti                             ; now it seams safe to enable interrupts
    xor ax, ax
    int 0x14                        ; setup serial console

    call main                       ; call main
    mov ax, 0xcafe
    hlt                             ; halt computer if main exits


align 0x100
main:                           ; main is the first stable state where we have stack
                                ; and ivt so we can detect erros and simple interupts
                                ; for io communication with serial
                                ; mains job is to load the challenge and switch to 64 bit
                                ; where we solve the challenge
                                ; and output result when done in 64bit mode as we don't have io
                                ; in 64 bit mode and im not setting up yet another idt!!
    push bp
    mov bp, sp
    sub sp, 0x20
    mov di, prompt
    call puts
    mov di, chall_in_out         ; now puts the input buffer as we also use it to store output
    call gets
    call setup_paging
    mov di, solve
    mov si, chall_in_out
    call call64bit
    mov di ,chall_in_out
    call puts
    mov di, prompt
    call puts
    mov di, 0x1400
    call puts
    mov sp, bp
    pop bp
    ret

call64bit:
    cli                         ; no interupts from here!
    save16regs
    mov [normal_stack], sp        ; save old rsp
    mov eax, 0xd000             ; point cr3 to page tables
    mov cr3, eax

    lgdt [gdtr]                 ; load global descriptor table

    mov eax, cr4
    or al, (1 << 5)             ; enable PAE
    mov cr4, eax

    mov ecx, 0xC0000080          ; Set the C-register to 0xC0000080, which is the EFER MSR.
    rdmsr                        ; Read from the model-specific register.
    or eax, 1 << 8               ; Set the LM-bit which is the 9th bit (bit 8).
    wrmsr                        ; Write to the model-specific register.

    mov eax, cr0
    or eax, 0x80000011
    mov cr0, eax
    jmp 0x08:bits64              ; crazy hack to hit jump trapoline for 64bit mode
    mov ax, 0xbeef
    hlt


setup_paging:                   ;will create linear mapping from virtual to physical in 64bit mode
    push ebx
    push ecx
    push edx
    mov eax, 0xe003
    mov [0xd000], eax           ;setup l1 page table
    mov ax, 0xf003
    mov [0xe000], eax           ;setup l2 page table

    mov ecx, 512
    mov eax, 0x0
    mov edx, 0xf000

    mapping_loop:
    mov ebx, eax
    shl ebx, 21
    or ebx, 0x83                ; create huge page tables in l3
    mov [edx], ebx
    add edx, 8
    add eax, 1
    loop mapping_loop
    pop edx
    pop ecx
    pop ebx
    ret

strlen:
    mov ax, 0
strlen_loop:
        add di, ax
        cmp byte [di], 0
        jz strlen_end
        inc ax
        jmp strlen_loop
strlen_end:
    ret

gets:                           ; slighly modified gets reading til null terminator as chall may contain \n
                                ;yee I know it's dangerous
                                ; hope this turns into a CTF chall so actually it's good right?
    call getc
    cmp al, 0x00
    je gets_end
    cmp al, 0xd
    je skipcr
    mov [di], al
    skipcr:
    inc di
    jmp gets
gets_end:
    inc di
    xor al, al
    mov [di], al
    ret

puts:
    mov al, 0
    mov si, di
puts_loop:
        mov al, [si]
        test al, al
        jz puts_end
        mov di, ax
        call putc
        inc si
        jmp puts_loop
puts_end:
    ret

uart_status:
    mov ah, 0x3
    int 0x14
    ret

putc:                           ; for now putc is just uartwrite
                                ; handle carriage return and oher later/never
uartwrite:
    call uart_status
    test al, 0x20
    jz uartwrite
    mov ah, 0x1
    int 0x14
    ret

getc:                           ; same argument as for putc
uart_read:
    call uart_status
    test al, 0x1
    jz uart_read
    mov ah, 0x2
    int 0x14
    ret

align 0x1000

    ;; here we write the 64 bit code segment
[bits 64]
solve:                          ; we are in long mode!!!!!
                                ; input in rdi
    push rbp
    mov rbp, rsp
    xor rax, rax
    xor rdx, rdx
    rdtsc
    shl rdx, 32
    or rax, rdx
    push rax

    push 0x0
    mov rbx, 0x0a
    xor rsi, rsi
solve_loop:
    test byte [rdi], 0xff
    jz solve_end
    cmp [rdi], bl
    jz next
    call strtoul
    add rsi, rax
    jmp solve_loop

next:
    push rsi
    inc rdi
    xor rsi, rsi
    cmp [rdi], bl
    je solve_end
    jmp solve_loop

solve_end:
    push rsi
    mov rdi, 0x1000
    mov rsi, 0x0030303030303030
    mov qword [rdi], rsi

    push 0
    pop rsi
pop_loop:
    pop rax
    test rax, rax
    jz pop_end
    cmp rax, rsi
    cmova rsi, rax
    jmp pop_loop

pop_end:
    mov rdi, 0x1006
    call to_ascii
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax
    pop rax
    xchg rax, rbx
    sub rax, rbx


    mov rdi, 0x1400
    mov rsi, 0x0030303030303030
    mov qword [rdi], rsi

    mov rsi, rax
    mov rdi, 0x1406
    call to_ascii

    mov rsp, rbp
    pop rbp
    ret

strtoul:
    xor rax, rax
    xor rcx, rcx
strtoul_loop:
    mov cl, [rdi]
    cmp cl, 0x0a
    je strtoul_end
    imul rax, 10
    sub rcx, '0'
    add rax, rcx
    inc rdi
    jmp strtoul_loop
strtoul_end:
    inc rdi
    ret

to_ascii:
    push rbp
to_ascii_loop:
    xor rax, rax
    xor rdx, rdx
    mov rax, rsi
    mov rdx, 0x00
    push 10
    pop rcx
    div rcx
    mov rsi, rax
    mov rbp, rdx
    add rbp, '0'
    xchg rax, rbp
    mov byte [rdi], al
    xchg rax, rbp
    dec rdi
    cmp rax, 0x0
    jne to_ascii_loop
    pop rbp
    ret

exit:
    ;; jmp $
    mov [retval64], ax
    xor rax, rax                ; ss
    push ax
    mov rax, 0x8000             ; rsp
    push ax
    mov rax, 0                  ; rflags
    push rax
    mov rax, 0x10               ; cs
    push rax
    mov rax, exit_trampoline
    push rax                    ; rip

    mov rcx, 0xC0000080          ; Set the C-register to 0xC0000080, which is the EFER MSR.
    rdmsr                        ; Read from the model-specific register.
    mov rax, 0x0
    wrmsr                        ; Write to the model-specific register.
                                 ; set LME = 0

    iretq                       ; jmp exit_trampoline


times 0xfff0-($-$$) db 0        ; The reset address of x86 cpus 0xf000:0xffff0 cs:eip or ip as we are in 16bit real mode
                                ; First addresse ever executed upon boot
                                ; (not conting internal CPU setup when only running from L cache's)

[bits 16]
jmp 0xf000:boot                 ; far jmp instruction to boot sequence
                                ; needs to be here!!


times 0x10000-($-$$) db 0       ; pad bios to 0x10000 length
                                ; python startup will prepend 0x30000

    ;; memory layout:
    ;;
    ;; ivt                      [0x0000:0x0000 - 0x0000:0x03ff]
    ;; global data              [0x0000:0x0400 - 0x0000:0x0fff]
    ;; chall input data         [0x0000:0x1000 - 0x0000:0xffff]
    ;; normal 16bit stack       [0x0000:0xa000 - 0x0000:0xafff]
    ;; interrupt stack          [0x0000:0xb000 - 0x0000:0xbfff]
    ;; l1 page tables           [0x0000:0xd000 - 0x0000:0xdfff]
    ;; l2 page tables           [0x0000:0xe000 - 0x0000:0xefff]
    ;; l3 page tables           [0x0000:0xf000 - 0x0000:0xffff]
    ;; ivt jump table           [0xf000:0x1000 - 0xf000:0x17ff]
    ;; io communication code    [0xf000:0x1800 - 0xf000:0x1fff]
    ;; boot and main code       [0xf000:0x2000 - 0xf000:0x2fff]
    ;; 64 bit code              [0xf000:0x3000 - 0xf000:0xffff]
    ;;
    ;; 64 bit stack             [0xfff000] paging (not in range from 16 bit so segmented addr makes no sence)
