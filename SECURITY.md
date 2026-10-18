# Security Policy

## Scope & Target Environments

This repository contains hypervisor research source code for virtualizing physical memory apertures mapped to Trusted Platform Module 2.0 (TPM 2.0) hardware devices.

| Component | Target Architecture | Status |
| :--- | :--- | :--- |
| Intel VT-x EPT Handler | x86_64 | Supported |
| CRB MMIO Emulation | x86_64 | Supported |
| TIS FIFO Emulation | x86_64 | Supported |
| AMD-V NPT Port | x86_64 | Research |

## Reporting Security Issues

To report hypervisor privilege escalation vectors, guest-to-host escape conditions, or speculative execution leaks, please contact:

- **Security Contact**: `adam@networkconnect.org`
- **PGP**: Available upon request.
