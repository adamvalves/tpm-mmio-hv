#include "tpm_mmio_hv.h"
#include <string.h>

static bool     g_mmio_on = false;
static uint32_t g_iface = 0;
static uint8_t  g_cmd[TPM_BUF_MAX];
static uint32_t g_cmd_len = 0;
static uint8_t  g_rsp[TPM_BUF_MAX];
static uint32_t g_rsp_len = 0;
static volatile uint8_t *g_tpm_va = NULL;
static bool     g_skip_mix = false;
static uint8_t  g_seed[32];

static inline uint16_t be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t tpm_cmd_cc(const uint8_t *cmd, uint32_t len) {
    if (!cmd || len < 10) return 0;
    return be32(cmd + 6);
}

static uint32_t tpm_cmd_handle(const uint8_t *cmd, uint32_t len) {
    if (!cmd || len < 14) return 0;
    if (tpm_cmd_cc(cmd, len) != TPM_CC_READ_PUBLIC) return 0;
    return be32(cmd + 10);
}

static bool tpm_rsa_unique_at(const uint8_t *buf, uint32_t size, uint32_t pub_start, uint32_t pub_end,
                              uint32_t *out_off, uint16_t *out_len, bool need_data) {
    static const uint16_t lens[4] = { 256, 128, 64, 32 };
    for (uint32_t i = 0; i < 4; i++) {
        uint16_t n = lens[i];
        if (pub_end < pub_start + 2u + n) continue;
        uint32_t sz_off = pub_end - 2u - n;
        if (sz_off < pub_start + 0x0Cu) continue;
        if (sz_off + 2u > size) continue;
        if (be16(buf + sz_off) != n) continue;
        if (need_data && sz_off + 2u + n > size) continue;
        if (out_off) *out_off = sz_off + 2;
        *out_len = n;
        return true;
    }
    return false;
}

static bool tpm_unique_loc(const uint8_t *buf, uint32_t size, uint32_t *out_off, uint16_t *out_len, bool need_data) {
    if (!buf || size < 0x12 || !out_len) return false;

    uint16_t tag = be16(buf);
    uint16_t public_size = 0;
    uint32_t pub_start = 0, pub_end = 0;
    uint16_t type = 0;

    if (size >= 10 && be32(buf + 6) == 0 &&
        (tag == TPM_ST_NO_SESSIONS || tag == TPM_ST_SESSIONS)) {
        uint32_t hdr = (tag == TPM_ST_SESSIONS) ? 14u : 10u;
        if (size < hdr + 4) return false;
        public_size = be16(buf + hdr);
        if (!public_size) return false;
        pub_start = hdr + 2;
        pub_end = pub_start + public_size;
        type = be16(buf + pub_start);
    } else if (tag >= 0x20u && tag <= 0x200u && size >= 4 &&
               (be16(buf + 2) == TPM_ALG_RSA || be16(buf + 2) == TPM_ALG_ECC)) {
        public_size = tag;
        pub_start = 2;
        pub_end = 2 + public_size;
        type = be16(buf + 2);
    } else {
        return false;
    }

    if (need_data && pub_end > size) return false;
    if (type == TPM_ALG_RSA) {
        return tpm_rsa_unique_at(buf, size, pub_start, pub_end, out_off, out_len, need_data);
    }

    if (type == TPM_ALG_ECC) {
        uint16_t auth = be16(buf + pub_start + 8);
        uint32_t off = pub_start + 10 + auth;
        if (off + 8 > size) return false;

        for (uint32_t i = 0; i < 8 && off + 4 < size; i++) {
            uint16_t w = be16(buf + off);
            if (w == 0x0010 || w == 0x0003) off += 2;
            else break;
        }
        if (off + 2 > size) return false;
        uint16_t n = be16(buf + off);
        uint32_t uniq = off;
        off += 2;
        if (!n || n > 80) return false;
        if (off + n + 2 > size) return false;
        uint16_t n2 = be16(buf + off + n);
        if (!n2) return false;
        uint16_t total = (uint16_t)(n + 2 + 2 + n2);
        if (total > TPM_MAX_UNIQUE) return false;
        if (need_data && uniq + total > size) return false;
        if (out_off) *out_off = uniq;
        *out_len = total;
        return true;
    }
    return false;
}

static bool unique_span(const uint8_t *buf, uint32_t size, uint32_t *off, uint32_t *len) {
    uint16_t n = 0;
    uint32_t o = 0;
    if (!off || !len) return false;
    if (!tpm_unique_loc(buf, size, &o, &n, false)) return false;
    *off = o;
    *len = n;
    return true;
}

static uint8_t mix_byte(uint32_t handle, uint32_t i, uint8_t orig) {
    uint8_t k = g_seed[i & 31];
    k ^= (uint8_t)(handle >> ((i & 3) * 8));
    k ^= (uint8_t)(i * 17u + 0xA5u);
    uint8_t d = (uint8_t)(orig ^ k);
    if (i == 0) d |= 0x80;
    return d;
}

static volatile uint8_t *tpm_hw_ptr(uint64_t pa) {
    if (pa < TPM_MMIO_BASE || pa >= TPM_MMIO_END) return NULL;
    if (g_tpm_va) return g_tpm_va + (pa - TPM_MMIO_BASE);
    return (volatile uint8_t *)pa;
}

static uint64_t tpm_hw_load(uint64_t pa, uint32_t n) {
    volatile uint8_t *p = tpm_hw_ptr(pa);
    uint64_t x = 0;
    if (!p || !n) return 0;
    for (uint32_t b = 0; b < n && b < 8; b++) {
        x |= (uint64_t)p[b] << (8 * b);
    }
    return x;
}

static void tpm_hw_store(uint64_t pa, uint64_t v, uint32_t n) {
    volatile uint8_t *p = tpm_hw_ptr(pa);
    if (!p || !n) return;
    for (uint32_t b = 0; b < n && b < 8; b++) {
        p[b] = (uint8_t)(v >> (8 * b));
    }
}

static void tpm_sniff_iface(uint64_t base) {
    if (g_iface) return;
    uint32_t id = (uint32_t)tpm_hw_load(base + 0x30, 4);
    switch (id & 0xFu) {
    case 0x1: g_iface = IFACE_CRB; break;
    case 0x0:
    case 0xF: g_iface = IFACE_TIS; break;
    default:  g_iface = IFACE_CRB; break;
    }
}

void tpm_hv_init(uint8_t *tpm_virtual_address, const uint8_t seed[32]) {
    g_tpm_va = tpm_virtual_address;
    if (seed) {
        memcpy(g_seed, seed, 32);
    } else {
        memset(g_seed, 0x42, 32);
    }
    g_mmio_on = true;
}

void tpm_hv_set_skip_mix(bool skip) {
    g_skip_mix = skip;
}

uint64_t tpm_hv_mmio_read(uint64_t gpa, uint32_t n) {
    uint64_t base = gpa & ~0xFFFULL;
    uint32_t off = (uint32_t)(gpa & 0xFFF);

    tpm_sniff_iface(base);

    if (g_iface == IFACE_CRB && off >= CRB_DATA) {
        uint32_t handle = tpm_cmd_handle(g_cmd, g_cmd_len);
        if (!handle) handle = 0x81010001u;

        uint64_t v = 0;
        uint32_t uoff = 0, ulen = 0;

        for (uint32_t i = 0; i < n; i++) {
            uint32_t idx = off - CRB_DATA + i;
            uint8_t b = (uint8_t)tpm_hw_load(gpa + i, 1);

            if (idx < TPM_BUF_MAX) {
                g_rsp[idx] = b;
                if (g_rsp_len < idx + 1) g_rsp_len = idx + 1;
            }

            bool span = !g_skip_mix && unique_span(g_rsp, g_rsp_len, &uoff, &ulen);
            if (span && idx >= uoff && idx < uoff + ulen) {
                b = mix_byte(handle, idx - uoff, b);
            }

            v |= (uint64_t)b << (8 * i);
        }
        return v;
    }

    if (g_iface == IFACE_TIS && off == TIS_FIFO) {
        uint32_t handle = tpm_cmd_handle(g_cmd, g_cmd_len);
        if (!handle) handle = 0x81010001u;

        uint64_t v = 0;
        uint32_t uoff = 0, ulen = 0;
        bool span = !g_skip_mix && unique_span(g_rsp, g_rsp_len, &uoff, &ulen);

        for (uint32_t i = 0; i < n; i++) {
            uint8_t b = (uint8_t)tpm_hw_load(gpa, 1);
            if (g_rsp_len < TPM_BUF_MAX) g_rsp[g_rsp_len++] = b;
            if (!span && !g_skip_mix) {
                span = unique_span(g_rsp, g_rsp_len, &uoff, &ulen);
            }
            if (span && g_rsp_len && (g_rsp_len - 1) >= uoff &&
                (g_rsp_len - 1) < uoff + ulen) {
                b = mix_byte(handle, (g_rsp_len - 1) - uoff, b);
            }
            v |= (uint64_t)b << (8 * i);
        }
        return v;
    }

    return tpm_hw_load(gpa, n);
}

void tpm_hv_mmio_write(uint64_t gpa, uint64_t val, uint32_t n) {
    uint64_t base = gpa & ~0xFFFULL;
    uint32_t off = (uint32_t)(gpa & 0xFFF);

    tpm_sniff_iface(base);

    if (g_iface == IFACE_CRB && off >= CRB_DATA && off < 0x1000) {
        for (uint32_t i = 0; i < n; i++) {
            uint32_t at = off - CRB_DATA + i;
            if (at < TPM_BUF_MAX) {
                g_cmd[at] = (uint8_t)(val >> (8 * i));
                if (g_cmd_len < at + 1) g_cmd_len = at + 1;
            }
        }
        tpm_hw_store(gpa, val, n);
        return;
    }

    if (g_iface == IFACE_CRB && off == CRB_START && (val & CRB_START_BIT)) {
        g_rsp_len = 0;
        tpm_hw_store(gpa, val, n);
        return;
    }

    if (g_iface == IFACE_CRB && off == CRB_REQUEST) {
        if (val & 2u) {
            g_rsp_len = 0;
            g_cmd_len = 0;
        }
    }

    if (g_iface == IFACE_TIS && off == TIS_FIFO) {
        for (uint32_t i = 0; i < n; i++) {
            if (g_cmd_len < TPM_BUF_MAX) {
                g_cmd[g_cmd_len++] = (uint8_t)(val >> (8 * i));
            }
        }
        tpm_hw_store(gpa, val, n);
        return;
    }

    if (g_iface == IFACE_TIS && off == TIS_STS && (val & TIS_STS_GO)) {
        g_rsp_len = 0;
        tpm_hw_store(gpa, val, n);
        return;
    }

    if (g_iface == IFACE_TIS && off == TIS_STS && (val & 0x40)) {
        g_cmd_len = 0;
        g_rsp_len = 0;
    }

    tpm_hw_store(gpa, val, n);
}
