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

    xor rax, rax                ; zero shit
    xor rbx, rbx
    xor rdx, rdx
    mov bl, [rdi]               ; put opponent in bl
    cmp bl, 0                   ; test if done
    jz done
    mov al, [rdi + 2]           ; put us in al

    sub al, 0x57                ; Use ascii to advantage 0x57 == 'X' - 1
    sub bl, 0x40                ; Use ascii to advantage 0x40 == 'A' - 1
    add r8, rax                 ; add bonus

    add bl, 2
    sub bl, al
    mov al, bl
    mov rbx, 3                  ; x == us == bl, y == opponent == al
    div rbx                     ; rdx = (2 + y - x) % 3

    ror dl, 1                   ; swap bit0 and bit1 in rdx
                                ; rotate right and left should be operators
    mov al, dl                  ; in all languages
    shr dl, 6
    or al, dl
    and al, 0x3                 ; store swap result in rax

    mov rbx, rax
    shl rax, 1
    add rax, rbx                ; rax = rax * 3

    add r8, rax                 ; add win/draw/loss
    add rdi, 4
    jmp solve_loop


done:                           ; print shit
    mov rax, r8                 ; result is now in rax
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
