# PLT trampoline for lazy binding
    .text
    .globl trampoline
    .hidden trampoline
    .type trampoline, @function
    .align 16

trampoline:

# Your code here
# save the context(registers)
    movq 0(%rsp), %rdi
    movq 8(%rsp), %rsi
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
    addq $16, %rsp
    jmp  *%rax
# Your code here
