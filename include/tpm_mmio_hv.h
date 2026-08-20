#ifndef TPM_MMIO_HV_H
#ifndef TPM_MMIO_HV_H
#define TPM_MMIO_HV_H

#include <stdint.h>
#include <stdbool.h>

#define TPM_MMIO_BASE        0xFED40000ULL
#define TPM_MMIO_PAGES       5u
#define TPM_MMIO_END         (TPM_MMIO_BASE + (TPM_MMIO_PAGES * 0x1000))
#define TPM_BUF_MAX          4096u

#define CRB_REQUEST          0x40u
#define CRB_START            0x4Cu
#define CRB_DATA             0x80u
#define CRB_START_BIT        1u

#define TIS_STS              0x18u
#define TIS_FIFO             0x24u
#define TIS_STS_GO           0x20u

#define IFACE_CRB            1u
#define IFACE_TIS            2u

#define TPM_CC_READ_PUBLIC   0x00000173u
#define TPM_ST_NO_SESSIONS   0x8001u
#define TPM_ST_SESSIONS      0x8002u
#define TPM_ALG_RSA          0x0001u
#define TPM_ALG_ECC          0x0023u
#define TPM_MAX_UNIQUE       256u

#ifdef __cplusplus
extern "C" {
#endif

void tpm_hv_init(uint8_t *tpm_virtual_address, const uint8_t seed[32]);
void tpm_hv_set_skip_mix(bool skip);
uint64_t tpm_hv_mmio_read(uint64_t gpa, uint32_t bytes);
void tpm_hv_mmio_write(uint64_t gpa, uint64_t value, uint32_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* TPM_MMIO_HV_H */
