# ============================================================================
# fe256_x86_64.S - x86_64 Assembly Optimizations for 256-bit Field Elements
# 
# High-performance field arithmetic for secp256k1 and SM2 curves.
# Uses BMI2 (MULX) and ADX (ADCX/ADOX) instructions when available.
#
# Platform Support:
# - Linux/macOS: System V AMD64 ABI
# - Windows/MinGW: Windows x64 ABI (different register convention)
#
# Calling convention: 
#   Linux/macOS: rdi, rsi, rdx, rcx, r8, r9
#   Windows:     rcx, rdx, r8, r9 (shadow space required)
#
# Author: knightc
# Copyright (c) 2019-2026 knightc. All rights reserved.
# License: Apache License 2.0
# ============================================================================

#ifdef __x86_64__

.intel_syntax noprefix

# ============================================================================
# Platform-specific macros
# ============================================================================

#ifdef _WIN32
/* Windows x64 ABI: Use different registers */
#define ARG1 rcx
#define ARG2 rdx
#define ARG3 r8
#define ARG4 r9
#else
/* System V AMD64 ABI (Linux/macOS) */
#define ARG1 rdi
#define ARG2 rsi
#define ARG3 rdx
#define ARG4 rcx
#endif

# ============================================================================
# Constants
# ============================================================================

.section .rodata
.align 32

# secp256k1 prime: p = 2^256 - 2^32 - 977
secp256k1_p:
    .quad 0xFFFFFFFEFFFFFC2F
    .quad 0xFFFFFFFFFFFFFFFF
    .quad 0xFFFFFFFFFFFFFFFF
    .quad 0xFFFFFFFFFFFFFFFF

# Reduction constant c = 2^32 + 977 = 0x1000003D1
secp256k1_c:
    .quad 0x1000003D1

# Montgomery constant n0 = -p^(-1) mod 2^64
secp256k1_n0:
    .quad 0xD838091DD2253531

# SM2 prime
sm2_p:
    .quad 0xFFFFFFFFFFFFFFFF
    .quad 0xFFFFFFFF00000000
    .quad 0xFFFFFFFFFFFFFFFF
    .quad 0xFFFFFFFEFFFFFFFF

# ============================================================================
# fe256_reduce_secp256k1_asm
#
# Fast reduction for 512-bit input using secp256k1's special form:
# 2^256 ≡ 2^32 + 977 (mod p)
#
# Input:  ARG1 = r (result pointer, 4 limbs)
#         ARG2 = a (input pointer, 8 limbs)
# ============================================================================

.section .text
.globl fe256_reduce_secp256k1_asm
.align 32
fe256_reduce_secp256k1_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
#ifdef _WIN32
    # Windows: save shadow space and use rcx, rdx
    mov rdi, rcx            # r -> rdi
    mov rsi, rdx            # a -> rsi
#endif
    
    # Load reduction constant c = 2^32 + 977
    mov rcx, 0x1000003D1
    
    # Load low 256 bits (a[0..3])
    mov r8,  [rsi]
    mov r9,  [rsi + 8]
    mov r10, [rsi + 16]
    mov r11, [rsi + 24]
    
    # Load high 256 bits (a[4..7])
    mov r12, [rsi + 32]
    mov r13, [rsi + 40]
    mov r14, [rsi + 48]
    mov r15, [rsi + 56]
    
    # Compute: r = low + high * c
    # where c = 0x1000003D1
    
    # r12 * c
    mov rax, r12
    mul rcx                  # rdx:rax = r12 * c
    add r8, rax
    adc r9, rdx
    mov rbx, 0
    adc rbx, 0               # Save carry
    
    # r13 * c
    mov rax, r13
    mul rcx
    add r9, rax
    adc r10, rdx
    adc rbx, 0
    add r9, rbx
    mov rbx, 0
    adc rbx, 0
    
    # r14 * c
    mov rax, r14
    mul rcx
    add r10, rax
    adc r11, rdx
    adc rbx, 0
    add r10, rbx
    mov rbx, 0
    adc rbx, 0
    
    # r15 * c
    mov rax, r15
    mul rcx
    add r11, rax
    adc rdx, 0
    add r11, rbx
    adc rdx, 0
    
    # If there's overflow (rdx > 0), multiply by c again
    mov rax, rdx
    mul rcx
    add r8, rax
    adc r9, rdx
    adc r10, 0
    adc r11, 0
    
    # Final conditional subtraction of p
    mov rax, r8
    mov rbx, r9
    mov rcx, r10
    mov rdx, r11
    
    lea rsi, [rip + secp256k1_p]
    sub rax, [rsi]
    sbb rbx, [rsi + 8]
    sbb rcx, [rsi + 16]
    sbb rdx, [rsi + 24]
    
    # If no borrow, use reduced value
    cmovc rax, r8
    cmovc rbx, r9
    cmovc rcx, r10
    cmovc rdx, r11
    
    # Store result
    mov [rdi], rax
    mov [rdi + 8], rbx
    mov [rdi + 16], rcx
    mov [rdi + 24], rdx
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# ============================================================================
# fe256_sqr_wide_asm
#
# 256-bit squaring: r = a^2 (512-bit result)
# Optimized squaring with fewer multiplications than full multiply
#
# Input:  ARG1 = r (result pointer, 8 limbs)
#         ARG2 = a (input pointer, 4 limbs)
# ============================================================================

.globl fe256_sqr_wide_asm
.align 32
fe256_sqr_wide_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    
#ifdef _WIN32
    mov rdi, rcx            # r -> rdi
    mov rsi, rdx            # a -> rsi
#endif
    
    # Load a
    mov r8,  [rsi]           # a[0]
    mov r9,  [rsi + 8]       # a[1]
    mov r10, [rsi + 16]      # a[2]
    mov r11, [rsi + 24]      # a[3]
    
    # Compute cross products (each appears twice)
    # a[0] * a[1], a[0] * a[2], a[0] * a[3]
    # a[1] * a[2], a[1] * a[3]
    # a[2] * a[3]
    
    # a[0]^2
    mov rax, r8
    mul r8
    mov [rdi], rax           # r[0]
    mov rbx, rdx             # carry
    
    # 2 * a[0] * a[1]
    mov rax, r8
    mul r9
    add rax, rax             # Double
    adc rdx, rdx
    add rbx, rax
    adc rdx, 0
    mov [rdi + 8], rbx       # r[1]
    mov rbx, rdx
    
    # 2 * a[0] * a[2] + a[1]^2
    mov rax, r8
    mul r10
    add rax, rax
    adc rdx, rdx
    mov r12, rax
    mov r13, rdx
    
    mov rax, r9
    mul r9
    add r12, rax
    adc r13, rdx
    add rbx, r12
    adc r13, 0
    mov [rdi + 16], rbx      # r[2]
    mov rbx, r13
    
    # 2 * a[0] * a[3] + 2 * a[1] * a[2]
    mov rax, r8
    mul r11
    add rax, rax
    adc rdx, rdx
    mov r12, rax
    mov r13, rdx
    
    mov rax, r9
    mul r10
    add rax, rax
    adc rdx, rdx
    add r12, rax
    adc r13, rdx
    add rbx, r12
    adc r13, 0
    mov [rdi + 24], rbx      # r[3]
    mov rbx, r13
    
    # 2 * a[1] * a[3] + a[2]^2
    mov rax, r9
    mul r11
    add rax, rax
    adc rdx, rdx
    mov r12, rax
    mov r13, rdx
    
    mov rax, r10
    mul r10
    add r12, rax
    adc r13, rdx
    add rbx, r12
    adc r13, 0
    mov [rdi + 32], rbx      # r[4]
    mov rbx, r13
    
    # 2 * a[2] * a[3]
    mov rax, r10
    mul r11
    add rax, rax
    adc rdx, rdx
    add rbx, rax
    adc rdx, 0
    mov [rdi + 40], rbx      # r[5]
    mov rbx, rdx
    
    # a[3]^2
    mov rax, r11
    mul r11
    add rbx, rax
    adc rdx, 0
    mov [rdi + 48], rbx      # r[6]
    mov [rdi + 56], rdx      # r[7]
    
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# ============================================================================
# fe256_mul_wide_asm
#
# 256-bit multiplication: r = a * b (512-bit result)
# Schoolbook multiplication optimized for x86_64
#
# Input:  ARG1 = r (result pointer, 8 limbs)
#         ARG2 = a (input pointer, 4 limbs)
#         ARG3 = b (input pointer, 4 limbs)
# ============================================================================

.globl fe256_mul_wide_asm
.align 32
fe256_mul_wide_asm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    
#ifdef _WIN32
    # Windows: rcx=r, rdx=a, r8=b
    mov rdi, rcx             # r -> rdi
    mov rsi, rdx             # a -> rsi
    mov rbp, r8              # b -> rbp
#else
    # System V: rdi=r, rsi=a, rdx=b
    mov rbp, rdx             # b -> rbp (save rdx before it's clobbered)
#endif
    
    # Load a[0..3] into r8..r11
    mov r8,  [rsi]           # a[0]
    mov r9,  [rsi + 8]       # a[1]
    mov r10, [rsi + 16]      # a[2]
    mov r11, [rsi + 24]      # a[3]
    
    # Column 0: a[0] * b[0]
    mov rax, r8
    mul qword ptr [rbp]      # rdx:rax = a[0] * b[0]
    mov [rdi], rax           # r[0]
    mov r12, rdx             # acc0
    xor r13d, r13d           # acc1 = 0
    
    # Column 1: a[0]*b[1] + a[1]*b[0]
    mov rax, r8
    mul qword ptr [rbp + 8]  # a[0] * b[1]
    add r12, rax
    adc r13, rdx
    xor r14d, r14d
    adc r14, 0
    
    mov rax, r9
    mul qword ptr [rbp]      # a[1] * b[0]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov [rdi + 8], r12       # r[1]
    mov r12, r13
    mov r13, r14
    xor r14d, r14d
    
    # Column 2: a[0]*b[2] + a[1]*b[1] + a[2]*b[0]
    mov rax, r8
    mul qword ptr [rbp + 16] # a[0] * b[2]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r9
    mul qword ptr [rbp + 8]  # a[1] * b[1]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r10
    mul qword ptr [rbp]      # a[2] * b[0]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov [rdi + 16], r12      # r[2]
    mov r12, r13
    mov r13, r14
    xor r14d, r14d
    
    # Column 3: a[0]*b[3] + a[1]*b[2] + a[2]*b[1] + a[3]*b[0]
    mov rax, r8
    mul qword ptr [rbp + 24] # a[0] * b[3]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r9
    mul qword ptr [rbp + 16] # a[1] * b[2]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r10
    mul qword ptr [rbp + 8]  # a[2] * b[1]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r11
    mul qword ptr [rbp]      # a[3] * b[0]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov [rdi + 24], r12      # r[3]
    mov r12, r13
    mov r13, r14
    xor r14d, r14d
    
    # Column 4: a[1]*b[3] + a[2]*b[2] + a[3]*b[1]
    mov rax, r9
    mul qword ptr [rbp + 24] # a[1] * b[3]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r10
    mul qword ptr [rbp + 16] # a[2] * b[2]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r11
    mul qword ptr [rbp + 8]  # a[3] * b[1]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov [rdi + 32], r12      # r[4]
    mov r12, r13
    mov r13, r14
    xor r14d, r14d
    
    # Column 5: a[2]*b[3] + a[3]*b[2]
    mov rax, r10
    mul qword ptr [rbp + 24] # a[2] * b[3]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov rax, r11
    mul qword ptr [rbp + 16] # a[3] * b[2]
    add r12, rax
    adc r13, rdx
    adc r14, 0
    
    mov [rdi + 40], r12      # r[5]
    mov r12, r13
    mov r13, r14
    
    # Column 6: a[3]*b[3]
    mov rax, r11
    mul qword ptr [rbp + 24] # a[3] * b[3]
    add r12, rax
    adc r13, rdx
    
    mov [rdi + 48], r12      # r[6]
    mov [rdi + 56], r13      # r[7]
    
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

#endif /* __x86_64__ */

# Prevent executable stack on Linux
#ifndef _WIN32
.section .note.GNU-stack,"",@progbits
#endif
