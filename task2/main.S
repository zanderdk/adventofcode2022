[bits 64]

;; A,X = ROCK     = 1
;; B,Y = PAPER    = 2
;; C,Z = SCISSORS = 3
;; example input:
;; A Y
;; B X
;; C Z\x00
;; loss = 0, draw = 3, win = 6

solve:                          ; we are in long mode!!!!!
                                ; input in rdi
    ;; push rbp                 ; fuck saving stack we can solve this only using register
    ;; mov rbp, rsp             ; don't ever say a compiler can optimze as good as humans

    ;; we don't even use any bacnhing no if statement or conditional moves only bit magic and a single loop

    ;; solve shit here!
    xor r8, r8                  ; clear our score
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r10, rax                ; save clock cycles
solve_loop:
    ;; mov

    xor rax, rax                ; zero shit
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    mov bl, [rdi]               ; put opponent bl
    cmp bl, 0                   ; test if done
    jz done
    mov al, [rdi + 2]           ; put us in al

    sub al, 0x57                ; Use ascii to advantage 0x57 == 'X' - 1
    sub bl, 0x40                ; Use ascii to advantage 0x40 == 'A' - 1
    add r8, rax                 ; add bonus

    add bl, 2
    sub bl, al
    mov al, bl
    mov rbx, 3                  ; x = us y = opponent
    div rbx                     ; rdx = (2 + y - x) % 3

    mov rax, rdx                ; swab bit 0 and 1 in n aka rax
    mov rbx, rax
    and rbx, 1                  ; bit0 = n >> 0
    mov rcx, rax
    shr rcx, 1                  ; bit1 = n >> 1

    xor rbx, rcx                ; bit0 ^ bit1
    mov rcx, rbx

    shl rbx, 1
    ;; shl rcx, 0                  ; not needed cause we swap 1 and 0

    or  rbx, rcx
    xor rax, rbx                ; bit 0 and 1 swaped
    mov rbx, rax
    shl rax, 1
    add rax, rbx                ; rax = rax * 3

    add r8, rax                 ; add win/draw/loss
    add rdi, 4
    jmp solve_loop


done:                           ; print shit
    mov rax, r8
    mov rdi, 0x1000
    mov rsi, 0x0030303030303030 ; put ascii zero in output
    mov qword [rdi], rsi
    mov rdi, 0x1006
    mov rsi, rax
    call to_ascii               ; create ascii string
    ;; print rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r10                ; calc execution time in rax
    ;; leave                    ; we don't need to clean stack as we do not use stack at all
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
