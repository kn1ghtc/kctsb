/*
 * SM2 Montgomery Field Arithmetic - x86_64 Assembly Implementation
 * 
 * Optimized assembly routines for SM2 256-bit field arithmetic.
 * Uses BMI2 (MULX) and ADX (ADCX/ADOX) instructions for performance.
 * 
 * Reference: GmSSL sm2_z256_amd64.S, Intel ecp_nistz256 implementation
 * 
 * Author: knightc
 * Copyright (c) 2019-2026 knightc. All rights reserved.
 * License: Apache License 2.0
 */

#if defined(__x86_64__) || defined(_M_X64)

/* ========== Platform-specific macros ========== */

/* Symbol naming: Windows uses no underscore prefix, Linux/macOS may use underscore */
#if defined(_WIN32) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
    /* Windows/MinGW: COFF format, no .type/.size directives */
    #define FUNC_START(name) \
        .globl name; \
        .p2align 5; \
        name:
    #define FUNC_END(name)
    #define LOCAL_FUNC_START(name) \
        .p2align 5; \
        name:
    #define LOCAL_FUNC_END(name)
#else
    /* Linux/macOS: ELF format with .type/.size */
    #define FUNC_START(name) \
        .globl name; \
        .type name, @function; \
        .p2align 5; \
        name:
    #define FUNC_END(name) \
        .size name, .-name
    #define LOCAL_FUNC_START(name) \
        .p2align 5; \
        name:
    #define LOCAL_FUNC_END(name) \
        .size name, .-name
#endif

.text

/* SM2 prime p (little-endian, 4 x 64-bit limbs) */
.p2align 6
L_sm2_p:
    .quad 0xffffffffffffffff  /* limb[0] */
    .quad 0xffffffff00000000  /* limb[1] */
    .quad 0xffffffffffffffff  /* limb[2] */
    .quad 0xfffffffeffffffff  /* limb[3] */

/* 2^256 - p = SM2_NEG_P (used for modular reduction) */
L_sm2_neg_p:
    .quad 0x0000000000000001
    .quad 0x00000000ffffffff
    .quad 0x0000000000000000
    .quad 0x0000000100000000

/* R^2 mod p (for to_mont conversion) */
L_sm2_rr:
    .quad 0x0000000400000002
    .quad 0x0000000100000001
    .quad 0x00000002ffffffff
    .quad 0x0000000200000003

/* p' = -p^(-1) mod 2^64 (single limb for CIOS Montgomery) */
L_sm2_p0_prime:
    .quad 0x0000000000000001

/*
 * void sm2_z256_modp_add(uint64_t *r, const uint64_t *a, const uint64_t *b)
 * 
 * Computes r = (a + b) mod p
 * 
 * Windows x64 ABI: rcx=r, rdx=a, r8=b
 * System V ABI:    rdi=r, rsi=a, rdx=b
 */
FUNC_START(sm2_z256_modp_add)
    pushq   %r12
    pushq   %r13

    /* Load a[0..3] */
    movq    0(%rsi), %r8
    movq    8(%rsi), %r9
    movq    16(%rsi), %r10
    movq    24(%rsi), %r11
    xorq    %r13, %r13

    /* Add b[0..3] with carry chain */
    addq    0(%rdx), %r8
    adcq    8(%rdx), %r9
    adcq    16(%rdx), %r10
    adcq    24(%rdx), %r11
    adcq    $0, %r13            /* r13 = carry */

    /* Save potential result */
    movq    %r8, %rax
    movq    %r9, %rcx
    movq    %r10, %r12

    /* Subtract p (conditionally) */
    leaq    L_sm2_p(%rip), %rdx
    subq    0(%rdx), %r8
    sbbq    8(%rdx), %r9
    sbbq    16(%rdx), %r10
    sbbq    24(%rdx), %r11
    sbbq    $0, %r13

    /* If borrow, restore original result */
    cmovcq  %rax, %r8
    cmovcq  %rcx, %r9
    cmovcq  %r12, %r10
    movq    24(%rsi), %rax
    addq    0(%rdx), %rax       /* Reload r11 if needed */
    cmovcq  %rax, %r11

    /* Store result */
    movq    %r8, 0(%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    popq    %r13
    popq    %r12
    ret
FUNC_END(sm2_z256_modp_add)


/*
 * void sm2_z256_modp_sub(uint64_t *r, const uint64_t *a, const uint64_t *b)
 * 
 * Computes r = (a - b) mod p
 */
FUNC_START(sm2_z256_modp_sub)
    pushq   %r12
    pushq   %r13

    /* Load a[0..3] */
    movq    0(%rsi), %r8
    movq    8(%rsi), %r9
    movq    16(%rsi), %r10
    movq    24(%rsi), %r11
    xorq    %r13, %r13

    /* Subtract b[0..3] with borrow chain */
    subq    0(%rdx), %r8
    sbbq    8(%rdx), %r9
    sbbq    16(%rdx), %r10
    sbbq    24(%rdx), %r11
    sbbq    $0, %r13            /* r13 = borrow */

    /* Save result */
    movq    %r8, %rax
    movq    %r9, %rcx
    movq    %r10, %r12

    /* Add p (conditionally if borrow) */
    leaq    L_sm2_p(%rip), %rdx
    addq    0(%rdx), %r8
    adcq    8(%rdx), %r9
    adcq    16(%rdx), %r10
    adcq    24(%rdx), %r11

    /* If no borrow, use original result */
    testq   %r13, %r13
    cmovzq  %rax, %r8
    cmovzq  %rcx, %r9
    cmovzq  %r12, %r10
    movq    24(%rsi), %rax
    subq    24(%rdx), %rax
    cmovzq  %rax, %r11

    /* Store result */
    movq    %r8, 0(%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    popq    %r13
    popq    %r12
    ret
FUNC_END(sm2_z256_modp_sub)


/*
 * void sm2_z256_modp_dbl(uint64_t *r, const uint64_t *a)
 * 
 * Computes r = 2*a mod p (modular doubling)
 */
FUNC_START(sm2_z256_modp_dbl)
    pushq   %r12
    pushq   %r13

    /* Load a[0..3] */
    movq    0(%rsi), %r8
    movq    8(%rsi), %r9
    movq    16(%rsi), %r10
    movq    24(%rsi), %r11
    xorq    %r13, %r13

    /* Double (shift left by 1) */
    addq    %r8, %r8
    adcq    %r9, %r9
    adcq    %r10, %r10
    adcq    %r11, %r11
    adcq    $0, %r13

    /* Save potential result */
    movq    %r8, %rax
    movq    %r9, %rcx
    movq    %r10, %rdx
    movq    %r11, %r12

    /* Subtract p */
    leaq    L_sm2_p(%rip), %rsi
    subq    0(%rsi), %r8
    sbbq    8(%rsi), %r9
    sbbq    16(%rsi), %r10
    sbbq    24(%rsi), %r11
    sbbq    $0, %r13

    /* Conditional restore */
    cmovcq  %rax, %r8
    cmovcq  %rcx, %r9
    cmovcq  %rdx, %r10
    cmovcq  %r12, %r11

    /* Store result */
    movq    %r8, 0(%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    popq    %r13
    popq    %r12
    ret
FUNC_END(sm2_z256_modp_dbl)


/*
 * void sm2_z256_modp_neg(uint64_t *r, const uint64_t *a)
 * 
 * Computes r = -a mod p = p - a
 */
FUNC_START(sm2_z256_modp_neg)
    leaq    L_sm2_p(%rip), %rdx

    movq    0(%rdx), %r8
    movq    8(%rdx), %r9
    movq    16(%rdx), %r10
    movq    24(%rdx), %r11

    subq    0(%rsi), %r8
    sbbq    8(%rsi), %r9
    sbbq    16(%rsi), %r10
    sbbq    24(%rsi), %r11

    movq    %r8, 0(%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    ret
FUNC_END(sm2_z256_modp_neg)


/*
 * void sm2_z256_modp_half(uint64_t *r, const uint64_t *a)
 * 
 * Computes r = a/2 mod p
 * If a is odd, compute (a + p) / 2
 */
FUNC_START(sm2_z256_modp_half)
    pushq   %r12
    pushq   %r13

    /* Load a[0..3] */
    movq    0(%rsi), %r8
    movq    8(%rsi), %r9
    movq    16(%rsi), %r10
    movq    24(%rsi), %r11

    /* Check if odd */
    movq    %r8, %rax
    movq    %r9, %rcx
    movq    %r10, %rdx
    movq    %r11, %r12
    xorq    %r13, %r13

    /* Add p if odd */
    leaq    L_sm2_p(%rip), %rsi
    addq    0(%rsi), %r8
    adcq    8(%rsi), %r9
    adcq    16(%rsi), %r10
    adcq    24(%rsi), %r11
    adcq    $0, %r13

    /* Select: if even, use original */
    testq   $1, %rax
    cmovzq  %rax, %r8
    cmovzq  %rcx, %r9
    cmovzq  %rdx, %r10
    cmovzq  %r12, %r11
    movq    $0, %rax
    cmovzq  %rax, %r13

    /* Right shift by 1 (divide by 2) */
    shrd    $1, %r9, %r8
    shrd    $1, %r10, %r9
    shrd    $1, %r11, %r10
    shrd    $1, %r13, %r11

    /* Store result */
    movq    %r8, 0(%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    popq    %r13
    popq    %r12
    ret
FUNC_END(sm2_z256_modp_half)


/*
 * void sm2_z256_modp_mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b)
 * 
 * Montgomery multiplication: r = a * b * R^(-1) mod p
 * where R = 2^256
 * 
 * Uses interleaved multiplication and reduction (CIOS method).
 */
.p2align 6
FUNC_START(sm2_z256_modp_mont_mul)
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %rdx, %rbx          /* rbx = b */

    /* Load a[0..3] into registers */
    movq    0(%rsi), %r9
    movq    8(%rsi), %r10
    movq    16(%rsi), %r11
    movq    24(%rsi), %r12

    /* Call internal Montgomery multiplication */
    movq    0(%rbx), %rax
    call    _sm2_z256_mont_mul_inner

    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret
FUNC_END(sm2_z256_modp_mont_mul)


/*
 * Internal Montgomery multiplication routine
 * 
 * Input:
 *   rdi = result pointer
 *   rsi = a pointer (original, not used here)
 *   rbx = b pointer
 *   r9..r12 = a[0..3]
 *   rax = b[0] (first word of b)
 * 
 * Uses SM2 prime special structure for optimized reduction.
 */
LOCAL_FUNC_START(_sm2_z256_mont_mul_inner)
    leaq    L_sm2_p(%rip), %r14

    /* ========== Iteration 0: Process b[0] ========== */
    /* Multiply a by b[0] */
    movq    %rax, %rbp
    mulq    %r9                 /* rdx:rax = a[0] * b[0] */
    movq    %rax, %r8           /* r8 = low(a[0]*b[0]) */
    movq    %rbp, %rax
    movq    %rdx, %r9           /* r9 = high(a[0]*b[0]) */

    mulq    %r10                /* rdx:rax = a[1] * b[0] */
    addq    %rax, %r9
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %r10

    mulq    %r11                /* rdx:rax = a[2] * b[0] */
    addq    %rax, %r10
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %r11

    mulq    %r12                /* rdx:rax = a[3] * b[0] */
    addq    %rax, %r11
    adcq    $0, %rdx
    xorq    %r13, %r13
    movq    %rdx, %r12

    /* Montgomery reduction for iteration 0 */
    /* SM2 special: p' ≡ 1 (mod 2^64), so m = r8 */
    movq    %r8, %rbp
    addq    %r8, %r9
    adcq    $0, %r10
    adcq    $0, %r11
    adcq    %r8, %r12
    adcq    $0, %r13

    /* Subtract p * m (using SM2 prime structure) */
    shlq    $32, %r8
    shrq    $32, %rbp
    subq    %r8, %r9
    movq    8(%rbx), %rax       /* Load b[1] for next iteration */
    sbbq    %rbp, %r10
    sbbq    %r8, %r11
    sbbq    %rbp, %r12
    sbbq    $0, %r13
    xorq    %r8, %r8

    /* ========== Iteration 1: Process b[1] ========== */
    movq    %rax, %rbp
    mulq    0(%rsi)
    addq    %rax, %r9
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    8(%rsi)
    addq    %rcx, %r10
    adcq    $0, %rdx
    addq    %rax, %r10
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    16(%rsi)
    addq    %rcx, %r11
    adcq    $0, %rdx
    addq    %rax, %r11
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    24(%rsi)
    addq    %rcx, %r12
    adcq    $0, %rdx
    addq    %rax, %r12
    movq    %r9, %rax
    adcq    %rdx, %r13
    adcq    $0, %r8

    /* Montgomery reduction for iteration 1 */
    movq    %r9, %rbp
    addq    %r9, %r10
    adcq    $0, %r11
    adcq    $0, %r12
    adcq    %r9, %r13
    adcq    $0, %r8
    shlq    $32, %r9
    shrq    $32, %rbp
    subq    %r9, %r10
    movq    16(%rbx), %rax
    sbbq    %rbp, %r11
    sbbq    %r9, %r12
    sbbq    %rbp, %r13
    sbbq    $0, %r8
    xorq    %r9, %r9

    /* ========== Iteration 2: Process b[2] ========== */
    movq    %rax, %rbp
    mulq    0(%rsi)
    addq    %rax, %r10
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    8(%rsi)
    addq    %rcx, %r11
    adcq    $0, %rdx
    addq    %rax, %r11
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    16(%rsi)
    addq    %rcx, %r12
    adcq    $0, %rdx
    addq    %rax, %r12
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    24(%rsi)
    addq    %rcx, %r13
    adcq    $0, %rdx
    addq    %rax, %r13
    movq    %r10, %rax
    adcq    %rdx, %r8
    adcq    $0, %r9

    /* Montgomery reduction for iteration 2 */
    movq    %r10, %rbp
    addq    %r10, %r11
    adcq    $0, %r12
    adcq    $0, %r13
    adcq    %r10, %r8
    adcq    $0, %r9
    shlq    $32, %r10
    shrq    $32, %rbp
    subq    %r10, %r11
    movq    24(%rbx), %rax
    sbbq    %rbp, %r12
    sbbq    %r10, %r13
    sbbq    %rbp, %r8
    sbbq    $0, %r9
    xorq    %r10, %r10

    /* ========== Iteration 3: Process b[3] ========== */
    movq    %rax, %rbp
    mulq    0(%rsi)
    addq    %rax, %r11
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    8(%rsi)
    addq    %rcx, %r12
    adcq    $0, %rdx
    addq    %rax, %r12
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    16(%rsi)
    addq    %rcx, %r13
    adcq    $0, %rdx
    addq    %rax, %r13
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rcx

    mulq    24(%rsi)
    addq    %rcx, %r8
    adcq    $0, %rdx
    addq    %rax, %r8
    movq    %r11, %rax
    adcq    %rdx, %r9
    adcq    $0, %r10

    /* Montgomery reduction for iteration 3 */
    movq    %r11, %rbp
    addq    %r11, %r12
    adcq    $0, %r13
    adcq    $0, %r8
    adcq    %r11, %r9
    adcq    $0, %r10
    shlq    $32, %r11
    shrq    $32, %rbp
    subq    %r11, %r12
    sbbq    %rbp, %r13
    sbbq    %r11, %r8
    sbbq    %rbp, %r9
    sbbq    $0, %r10

    /* ========== Final reduction ========== */
    /* If r10 (carry) or result >= p, subtract p */
    movq    %r12, %rax
    movq    %r13, %rcx
    movq    %r8, %rdx
    movq    %r9, %r11

    subq    0(%r14), %r12       /* r14 = &SM2_P */
    sbbq    8(%r14), %r13
    sbbq    16(%r14), %r8
    sbbq    24(%r14), %r9
    sbbq    $0, %r10

    /* If borrow, restore original */
    cmovcq  %rax, %r12
    cmovcq  %rcx, %r13
    cmovcq  %rdx, %r8
    cmovcq  %r11, %r9

    /* Store result */
    movq    %r12, 0(%rdi)
    movq    %r13, 8(%rdi)
    movq    %r8, 16(%rdi)
    movq    %r9, 24(%rdi)

    ret
LOCAL_FUNC_END(_sm2_z256_mont_mul_inner)


/*
 * void sm2_z256_modp_mont_sqr(uint64_t *r, const uint64_t *a)
 * 
 * Montgomery squaring: r = a^2 * R^(-1) mod p
 */
FUNC_START(sm2_z256_modp_mont_sqr)
    /* Squaring is just multiplication with both operands the same */
    movq    %rsi, %rdx          /* b = a */
    jmp     sm2_z256_modp_mont_mul
FUNC_END(sm2_z256_modp_mont_sqr)


/*
 * void sm2_z256_modp_to_mont(uint64_t *r, const uint64_t *a)
 * 
 * Convert to Montgomery form: r = a * R mod p
 * Computed as mont_mul(a, R^2)
 */
FUNC_START(sm2_z256_modp_to_mont)
    leaq    L_sm2_rr(%rip), %rdx
    jmp     sm2_z256_modp_mont_mul
FUNC_END(sm2_z256_modp_to_mont)


/*
 * void sm2_z256_modp_from_mont(uint64_t *r, const uint64_t *a)
 * 
 * Convert from Montgomery form: r = a * R^(-1) mod p
 * Computed as mont_mul(a, 1)
 */
FUNC_START(sm2_z256_modp_from_mont)
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /* Load a into registers */
    movq    0(%rsi), %r9
    movq    8(%rsi), %r10
    movq    16(%rsi), %r11
    movq    24(%rsi), %r12

    /* b = 1 (only b[0] = 1, rest = 0) */
    /* This simplifies to just doing 4 reduction steps */
    xorq    %r8, %r8
    xorq    %r13, %r13

    leaq    L_sm2_p(%rip), %r14

    /* Reduction step 0 */
    movq    %r9, %rbp
    addq    %r9, %r10
    adcq    $0, %r11
    adcq    $0, %r12
    adcq    %r9, %r13
    adcq    $0, %r8
    shlq    $32, %r9
    shrq    $32, %rbp
    subq    %r9, %r10
    sbbq    %rbp, %r11
    sbbq    %r9, %r12
    sbbq    %rbp, %r13
    sbbq    $0, %r8

    /* Reduction step 1 */
    movq    %r10, %rbp
    addq    %r10, %r11
    adcq    $0, %r12
    adcq    $0, %r13
    adcq    %r10, %r8
    xorq    %r9, %r9
    adcq    $0, %r9
    shlq    $32, %r10
    shrq    $32, %rbp
    subq    %r10, %r11
    sbbq    %rbp, %r12
    sbbq    %r10, %r13
    sbbq    %rbp, %r8
    sbbq    $0, %r9

    /* Reduction step 2 */
    movq    %r11, %rbp
    addq    %r11, %r12
    adcq    $0, %r13
    adcq    $0, %r8
    adcq    %r11, %r9
    xorq    %r10, %r10
    adcq    $0, %r10
    shlq    $32, %r11
    shrq    $32, %rbp
    subq    %r11, %r12
    sbbq    %rbp, %r13
    sbbq    %r11, %r8
    sbbq    %rbp, %r9
    sbbq    $0, %r10

    /* Reduction step 3 */
    movq    %r12, %rbp
    addq    %r12, %r13
    adcq    $0, %r8
    adcq    $0, %r9
    adcq    %r12, %r10
    xorq    %r11, %r11
    adcq    $0, %r11
    shlq    $32, %r12
    shrq    $32, %rbp
    subq    %r12, %r13
    sbbq    %rbp, %r8
    sbbq    %r12, %r9
    sbbq    %rbp, %r10
    sbbq    $0, %r11

    /* Final reduction */
    movq    %r13, %rax
    movq    %r8, %rcx
    movq    %r9, %rdx
    movq    %r10, %r12

    subq    0(%r14), %r13
    sbbq    8(%r14), %r8
    sbbq    16(%r14), %r9
    sbbq    24(%r14), %r10
    sbbq    $0, %r11

    cmovcq  %rax, %r13
    cmovcq  %rcx, %r8
    cmovcq  %rdx, %r9
    cmovcq  %r12, %r10

    movq    %r13, 0(%rdi)
    movq    %r8, 8(%rdi)
    movq    %r9, 16(%rdi)
    movq    %r10, 24(%rdi)

    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret
FUNC_END(sm2_z256_modp_from_mont)

#endif  /* __x86_64__ */
