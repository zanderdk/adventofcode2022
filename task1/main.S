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
