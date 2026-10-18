# Hardware Virtualization Architecture & TPM 2.0 Interception

## EPT Violation Interception Model

The hypervisor manages the guest physical address (GPA) mapping for the TPM 2.0 physical aperture. The target MMIO region resides across 5 physical 4KB pages:
- **Base GPA**: `0xFED40000`
- **End GPA**: `0xFED45000`

In the hypervisor's Extended Page Table (EPT) paging hierarchy, the corresponding EPT leaf entries are stripped of read (`Bit 0`) and write (`Bit 1`) permissions:

```text
[ Guest OS Ring 0 ] ──► MMIO Access (GPA: 0xFED40000)
                              │
                              ▼
                        [ EPT Fault ] (Exit Reason: EXIT_REASON_EPT_VIOLATION)
                              │
                              ▼
                     [ VM-Exit Dispatcher ]
                              │
                              ▼
                   [ tpm_hv_mmio_read / write ]
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
    [ CRB State Machine ]               [ TIS State Machine ]
    - Locality: 0xFED40000              - STS Register: 0x18
    - CRB_START: 0x4C                   - FIFO Window:  0x24
    - Data Window: 0x80                 - GO Bit:       0x20
            │                                   │
            └─────────────────┬─────────────────┘
                              ▼
                  [ Command Execution Hook ]
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
[ Command != READ_PUBLIC ]          [ Command == TPM_CC_READ_PUBLIC ]
- Passthrough to Hardware           - Intercept Public Response
                                    - Deterministic Key Derivation
                                    - Rewrite RSA / ECC Unique Public Key
```

## Command Parsing & Payload Modification

When a TPM 2.0 transaction executes `TPM_CC_READ_PUBLIC` (`0x00000173`), the hypervisor parses the response packet structure:

```text
+-----------------------+------------------+------------------------------------------+
| TPM Response Field    | Size (Bytes)     | Description                              |
+-----------------------+------------------+------------------------------------------+
| tag                   | 2                | TPM_ST_NO_SESSIONS / TPM_ST_SESSIONS     |
| responseSize          | 4                | Total response byte length (Big Endian)  |
| responseCode          | 4                | TPM_RC_SUCCESS (0x00000000)              |
| outPublic.type        | 2                | TPM_ALG_RSA (0x01) / TPM_ALG_ECC (0x23)  |
| outPublic.nameAlg     | 2                | Hashing algorithm (e.g., TPM_ALG_SHA256) |
| outPublic.objectAttr  | 4                | Object attributes bitmask                |
| outPublic.authPolicy  | 2 + Length       | Authorization policy digest              |
| outPublic.parameters  | Variable         | Key algorithm parameters                 |
| outPublic.unique      | 2 + KeyLength    | Public Key Buffer (Target for mutation)  |
+-----------------------+------------------+------------------------------------------+
```

### Key Modification Mechanics

1. **Length Validation**: The parser reads the 2-byte big-endian `unique.size` field.
2. **Deterministic Mutation**: A 32-byte cryptographic seed is mixed with the key algorithm and locality parameters using a sponge function to yield reproducible synthetic public keys.
3. **Hardware Isolation**: Physical hardware registers receive the unmodified command; only the return packet inspected by guest OS attestation routines is mutated in the hypervisor buffer before VM-entry resumption.
