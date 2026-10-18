# Contributing Guidelines

Contributions to `tpm-mmio-hv` must adhere to rigorous systems programming and hardware virtualization standards.

## Engineering Standards

1. **Deterministic Execution**:
   - VM-exit handlers execute in VMX root operation. Code must be deterministic, non-blocking, and free of dynamic allocations (`malloc` / pool allocations during hot paths).
2. **Bounds Validation**:
   - Every MMIO read/write access must strictly validate Guest Physical Address (GPA) offsets within the 5-page window (`0xFED40000` to `0xFED45000`).
   - TPM buffer copies must be strictly bounded by `TPM_BUF_MAX` (4096 bytes).
3. **Coding Style**:
   - Standard C99/C11.
   - Clean include guards (`#ifndef TPM_MMIO_HV_H`).
   - Zero emojis in all commits, comments, and documentation.
   - All documentation in formal technical English.
