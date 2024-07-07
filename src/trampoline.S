# PLT trampoline for lazy binding
    .text
    .globl trampoline
    .hidden trampoline
    .type trampoline, @function
    .align 16

trampoline:

# Your code here
# save the context(registers)
    movq  %rsp, %r11
    push  %rdi
    push  %rsi
    push  %rcx
    push  %r8
    push  %r9
    movq 0(%r11), %rdi
    movq 8(%r11), %rsi
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    call runtimeResolve
# restore the context(registers)
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbx
    pop  %rbp
    pop  %r9
    pop  %r8
    pop  %rcx
    pop  %rsi
    pop  %rdi
    addq $16, %rsp
    jmp  *%rax
# Your code here
