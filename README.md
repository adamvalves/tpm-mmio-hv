# TPM 2.0 MMIO Hypervisor Virtualization & Interception Framework

A low-level Intel VT-x Second-Level Address Translation (EPT) framework for intercepting, emulating, and dynamically modifying Trusted Platform Module (TPM 2.0) Memory-Mapped I/O (MMIO) transactions.

By establishing EPT violation traps over the physical MMIO page range (`0xFED40000` - `0xFED45000`), this framework intercepts raw guest access to both CRB (Command Response Buffer) and TIS (TPM Interface Specification) hardware registers. It provides real-time parsing of TPM command structures (including `TPM_CC_READ_PUBLIC`), allowing selective cryptographic response modification while bypassing static kernel driver inspection.

---

## Architecture Overview

```
+-------------------------------------------------------------------------+
|                              Guest Operating System                     |
|                                                                         |
|  +---------------------------+             +-------------------------+  |
|  |  Windows kernel (tpm.sys) |             | User Application / WMI  |  |
|  |  (Direct HW Pass-through) |             | (Filtered Response)     |  |
|  +---------------------------+             +-------------------------+  |
|                |                                        |               |
|                +-------------------+--------------------+               |
|                                    |                                    |
|                        MMIO Read/Write (0xFED40000)                     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                        Hypervisor (Intel VT-x / EPT)                    |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |  EPT Trap Handler (Locality 0..4, 4KB PTEs: R=0, W=0, X=1)       |  |
|  +-------------------------------------------------------------------+  |
|                                    |                                    |
|                 +------------------+------------------+                 |
|                 |                                     |                 |
|                 v                                     v                 |
|   [ RIP in tpm.sys? ]                   [ Target Command Intercept ]    |
|   -> Raw HW Pass-through                -> Parse TPM_CC_READ_PUBLIC     |
|                                         -> Dynamic Response Modification|
+-------------------------------------------------------------------------+
```

---

## Key Features

1. **Dual Interface MMIO Emulation**: Supports both TPM 2.0 CRB (Command Response Buffer) and TIS (TPM Interface Specification FIFO) register sets.
2. **Selective RIP Filtering**: Evaluates guest instruction pointers (`RIP`) during EPT violations. Operations originating from `tpm.sys` bypass byte transformation to prevent OS instability and driver attestation failures.
3. **Dynamic Structure Parsing**: Parses inbound TPM command buffers for `TPM_CC_READ_PUBLIC` (Command Code `0x00000173`) to identify RSA (2048/1024/512/256-bit) and ECC public key payload offsets.
4. **On-the-Fly Byte Transformation**: Applies seeded cryptographic byte mixing to unique hardware identity buffers during guest MMIO read operations.
5. **Page Table Splitting**: Demonstrates 2MB large page splitting into 4KB PTEs for Locality 0..4 MMIO pages (`0xFED40000` to `0xFED45000`), preserving adjacent IOAPIC and HPET MMIO mappings.

---

## Technical Specifications

### Target MMIO Layout

| Locality / Buffer | Address Range | Description |
| :--- | :--- | :--- |
| **Locality 0** | `0xFED40000` - `0xFED40FFF` | Primary OS / Kernel Access |
| **Locality 1** | `0xFED41000` - `0xFED41FFF` | Reserved Locality 1 |
| **Locality 2** | `0xFED42000` - `0xFED42FFF` | Reserved Locality 2 |
| **Locality 3** | `0xFED43000` - `0xFED43FFF` | Reserved Locality 3 |
| **Locality 4** | `0xFED44000` - `0xFED44FFF` | Firmware / TXT Locality |

### Supported Register Offsets

- **CRB Interface**:
  - `CRB_REQUEST` (`0x40`): Control Request Register.
  - `CRB_START` (`0x4C`): Command Execution Trigger.
  - `CRB_DATA` (`0x80`): Command & Response Data Buffer.
- **TIS Interface**:
  - `TIS_STS` (`0x18`): Status Register.
  - `TIS_FIFO` (`0x24`): Data FIFO Register.

---

## Integration Guide

### EPT Installation

```c
#include "tpm_mmio_hv.h"

void vmm_init_tpm_trap(void) {
    /* Split 2MB page at 0xFED00000 if necessary, then clear read/write permissions for Locality 0..4 */
    for (uint32_t i = 0; i < TPM_MMIO_PAGES; i++) {
        uint64_t target_gfn = (TPM_MMIO_BASE >> 12) + i;
        ept_set_permissions(target_gfn, /*read*/ 0, /*write*/ 0, /*exec*/ 1);
    }
}
```

### EPT Violation Dispatcher

```c
void vmm_handle_ept_violation(vcpu_t *vcpu, uint64_t gpa, uint64_t exit_qualification) {
    if (gpa >= TPM_MMIO_BASE && gpa < TPM_MMIO_END) {
        /* Determine if access originates from legitimate kernel driver */
        tpm_hv_set_skip_mix(vmm_is_rip_in_module(vcpu->rip, "tpm.sys"));

        /* Emulate MMIO instruction (mov, movsb, etc.) */
        if (!tpm_hv_emulate_mmio(vcpu, gpa, exit_qualification)) {
            /* Fallback to Monitor Trap Flag (MTF) single-step if instruction decoding fails */
            vmm_mtf_single_step_and_retrap(vcpu, gpa);
        }
        return;
    }
    
    /* Process other EPT violations */
}
```

---

## Repository Structure

```
tpm-mmio-hv/
├── README.md             # Technical architecture specification
├── LICENSE               # MIT License
├── include/
│   └── tpm_mmio_hv.h     # TPM MMIO hypervisor emulation headers
└── src/
    └── tpm_mmio_hv.c     # Core EPT MMIO emulation & buffer parsing engine
```

---

## License

Distributed under the MIT License. See `LICENSE` for details.
