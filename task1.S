[bits 16]
org 0x0                         ; actually this is at 0xf0000 as the code segement register is 0xf000 upon boot

ivt:                            ; macro loop for inserting ivt entries
%assign i 0
%rep    256
    dw 0x1000 + i*0x10          ; .data segment cannot be bigger than 0x1000
    dw 0xf000
%assign i i+1
%endrep

_ivt:
    dd 0x3ff                    ; limit idt
    dd 0x0                      ; base idt

normalstack:
    dw 0x7000
ivtstack:
    dw 0x9000

prompt:
    db '> ',0

align 0x1000                    ; actually data segment must be exactly 0x1000
datasegmentend:                 ; code segment starts here and is mapped to code selector 0xf000
                                ; code go brrr:

    ;;  ivt jump talbe here
%assign i 0
%rep    0x14
    cli                         ; no interupts while interupting
    mov ax, i
    jmp inthandler
    align 0x10
%assign i i+1
%endrep

jmp instructionint14handler     ; special handler for serial communication
align 0x10



align 0x1000                    ; end ivt jump talbe

inthandler:
mov bx, ax
mov eax, 0xdea0
hlt

    ;; boiler plate done for fault detection ivt
    ;; probably gonna need it for when i divide by 0 or some stupid shit later

instructionint14handler:
    cld
    mov [normalstack], sp
    mov sp, [ivtstack]
    push di
    push si
    push dx
    mov dx, di
    mov di, 0x14
    mov si, ax
    and si, 0xff00
    shr si, 8
    call instructionhandler
instexit:
    pop dx
    pop si
    pop di
    mov sp, [normalstack]
    iret                        ; iret will take care of restoring interuptflag and direction flag?

instructionhandler:
    cmp di, 0x14
    jne insterr
    mov di, si
    mov si, dx
    call serialhandle
    ret
insterr:
    mov eax, 0xdea1
    hlt

UART equ 0x3f8

serialhandle:
    cmp di, 0x0
    je serialinit
    cmp di, 0x2
    je serialread
    cmp di, 0x3
    je serialstatus
    cmp di, 0x1
    mov di, si
    je serialwrite
    ret

serialinit:
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

serialcheckfail:
    mov eax, 0xdea2
    hlt

serialwrite:
    push dx
    mov ax, di
    mov dx ,(UART + 0)
    out dx, al
    pop dx
    ret

serialread:
    push dx
    mov ax, 0x0
    mov dx ,(UART + 0)
    in al, dx
    pop dx
    ret

serialstatus:
    push dx
    mov ax, 0x0
    mov dx ,(UART + 5)
    in al, dx
    pop dx
    ret


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
    mov cx, datasegmentend
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
    mov sp, [ds:normalstack]        ; no recursion it could blow up the ivt

    lidt [_ivt]                     ; setup ivt
    mov ax, 0xf000
    mov fs, ax                      ; done setting up ivt
    mov eax, 0x10
    mov cr0, eax

    call setupinteruptcontroller
    mov di, 0x0
    call setirqbitmaskline          ; disable programable timer
    sti                             ; now it seams safe to enable interrupts
    xor ax, ax
    int 0x14                        ; setup serial console

    call main                       ; call main
    mov ax, 0xcafe
    hlt                             ; halt computer if main exits

iowait:
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

setupinteruptcontroller:        ; init pic 8259a
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
    call iowait

    mov dx, PIC2_COMMAND
    mov ax, (ICW1_INIT | ICW1_ICW4)
    out dx, al
    call iowait


    mov dx, PIC1_DATA
    mov ax, 0x60                        ; Master PIC vector offset
    out dx, al
    call iowait

    mov dx, PIC2_DATA
    mov ax, 0x68                        ; Slave PIC vector offset
    out dx, al
    call iowait


    mov dx, PIC1_DATA
    mov ax, 0x4                         ; Tell master PIC that there is a slave PIC at IRQ2
    out dx, al
    call iowait

    mov dx, PIC1_DATA
    mov ax, 0x2                         ; tell Slave PIC its cascade identity
    out dx, al
    call iowait


    mov dx, PIC1_DATA
    mov ax, ICW4_8086
    out dx, al
    call iowait

    mov dx, PIC1_DATA
    mov ax, ICW4_8086
    out dx, al
    call iowait

    mov dx, PIC2_DATA                   ; Restore mask inorder they were pushed
    pop ax
    out dx, al
    call iowait

    mov dx, PIC1_DATA
    pop ax
    out dx, al
    call iowait
    pop dx
    ret

setirqbitmaskline:
    push dx
    push bx
    push cx
    mov bx, PIC1_DATA
    mov dx, PIC2_DATA
    cmp di, 0x8
    jae setirqmoveskip
    mov dx, bx
setirqmoveskip:
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

clearirqbitmaskline:
    push dx
    push bx
    push cx
    mov bx, PIC1_DATA
    mov dx, PIC2_DATA
    cmp di, 0x8
    jae clearirqmovskip
    mov dx, bx
clearirqmovskip:
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

main:                           ; main
    push bp
    mov bp, sp
    sub sp, 0x20
    mov di, prompt
    call puts
    mov di, sp
    call gets
    mov di, sp
    call puts
    mov sp, bp
    pop bp
    jmp $

strlen:
    mov ax, 0
strlenloop:
        add di, ax
        cmp byte [di], 0
        jz strlenend
        inc ax
        jmp strlenloop
strlenend:
    ret

gets:                           ; yee I know it's dangerous
                                ; hope this turns into a CTF chall so actually it's good right?
    call getc
    cmp al, 0xa
    je getsend
    cmp al, 0xd
    je skipcr
    mov [di], al
    skipcr:
    inc di
    jmp gets
    getsend:
    inc di
    xor al, al
    mov [di], al
    ret

puts:
    mov al, 0
    mov si, di
putsloop:
        mov al, [si]
        test al, al
        jz putsend
        mov di, ax
        call putc
        inc si
        jmp putsloop
putsend:
    ret

uartstatus:
    mov ah, 0x3
    int 0x14
    ret

putc:                           ; for now putc is just uartwrite
                                ; handle carriage return and oher later/never
uartwrite:
    call uartstatus
    test al, 0x20
    jz uartwrite
    mov ah, 0x1
    int 0x14
    ret

getc:                           ; same argument as for putc
uartread:
    call uartstatus
    test al, 0x1
    jz uartread
    mov ah, 0x2
    int 0x14
    ret


times 0xfff0-($-$$) db 0        ; The reset address of x86 cpus 0xf000:0xffff0 cs:eip or ip as we are in 16bit real mode
                                ; First addresse ever executed upon boot
                                ; (not conting internal CPU setup when only running from L cache's)

jmp 0xf000:boot                 ; far jmp instruction to boot sequence
                                ; needs to be here!!


times 0x10000-($-$$) db 0       ; pad bios to 0x10000 length
                                ; python startup will prepend 0x30000
