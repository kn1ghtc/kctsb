# kctsb Troubleshooting & Bug Experience Summary

> **Purpose**: Document bugs, issues, and their solutions encountered during development.
> **Updated**: 2026-01-20 (Beijing Time, UTC+8)

This directory contains detailed analysis and solutions for issues encountered during kctsb development.

## Directory Structure

```
troubleshooting/
├── README.md                          # This file
├── fe256_data_type_issues.md          # Windows 64-bit data type issues
├── sm2_reduction_bug.md               # SM2 modular reduction bug
└── ecc_optimization_lessons.md        # ECC optimization lessons learned
```

## Quick Reference: Common Issues

### 1. Windows 64-bit Data Type Issues
**Symptom**: Incorrect field arithmetic results on Windows, tests pass on Linux.
**Root Cause**: `long` is 32-bit on Windows vs 64-bit on Linux.
**Solution**: Use `int64_t`/`uint64_t` instead of `long`/`unsigned long`.
**Details**: [fe256_data_type_issues.md](fe256_data_type_issues.md)

### 2. SM2 Signature Verification Intermittent Failures (~30% failure rate)
**Symptom**: SM2_SignVerify test fails randomly, ~30% failure rate.
**Root Cause**: Incomplete `fe256_reduce_sm2` implementation - missing proper Solinas reduction.
**Solution**: Implement correct SM2 Solinas reduction algorithm.
**Details**: [sm2_reduction_bug.md](sm2_reduction_bug.md)

### 3. P-256 Performance Optimization Attempts
**Symptom**: P-256 performance at ~2-5% of OpenSSL.
**Root Cause**: OpenSSL uses nistz256 assembly with ADX/BMI2 instructions.
**Lesson**: Pure C++ cannot match assembly-optimized code for this curve.
**Details**: [ecc_optimization_lessons.md](ecc_optimization_lessons.md)

## Development Guidelines Derived from These Issues

See [AGENTS.md](../../../AGENTS.md) for comprehensive development guidelines.
