## Summary of Changes
[Technical summary of the proposed hypervisor or MMIO interception improvements.]

## Functional Area
- [ ] CRB (Command Response Buffer) state machine
- [ ] TIS (TPM Interface Specification) FIFO handling
- [ ] TPM 2.0 command parser (`TPM_CC_READ_PUBLIC`, RSA/ECC unique public keys)
- [ ] Deterministic seed derivation / ChaCha20 / Keccak sponge
- [ ] Build configuration & toolchain

## Hardware & Environment Validation
- [ ] Validated on Intel VT-x with EPT enabled
- [ ] Validated TPM 2.0 command response (`tpm2_readpublic` / Windows TBS service)
- [ ] Verified guest operating system stability without NMI/watchdog timeouts
