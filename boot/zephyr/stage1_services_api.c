/*
 * Copyright (c) 2026 Stored Energy Systems
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

/**
 * Stage 1 (MCUboot) services API - the immutable-flash function table and
 * its retained-RAM locator. See boot/zephyr/include/stage1_services_api.h
 * for the ABI contract.
 *
 * This build ships the SOFTWARE crypto backend (whatever
 * bootutil/crypto/{sha,ecdsa}.h resolve to - TinyCrypt + ext/mbedtls-asn1
 * for ECDSA-P256).
 *
 */
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/util.h>

#include "bootutil/boot_record.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/bootutil_public.h" /* BOOT_MAGIC_SZ, BOOT_MAX_ALIGN */
#include "bootutil/bootutil_priv.h"   /* BOOT_IMG_MAGIC (boot_img_magic, .rodata) */
#include "bootutil/crypto/ecdsa.h"
#include "bootutil/crypto/sha.h"
#include "mcuboot_config/mcuboot_config.h"

BOOT_LOG_MODULE_DECLARE(mcuboot);

#include "stage1_services_api.h"
#include "stage1_services_publish.h"

BUILD_ASSERT(sizeof(bootutil_sha_context) <= sizeof(struct stage1_sha256_ctx),
             "stage1_sha256_ctx too small for the active SHA backend");

/* ---- SHA-256 ---- */

static int s1_sha256_init(struct stage1_sha256_ctx* ctx) {
  return bootutil_sha_init((bootutil_sha_context*)ctx) ? -EIO : 0;
}

static int s1_sha256_update(struct stage1_sha256_ctx* ctx, const uint8_t* in,
                            size_t len) {
  return bootutil_sha_update((bootutil_sha_context*)ctx, in, len) ? -EIO : 0;
}

static int s1_sha256_final(struct stage1_sha256_ctx* ctx, uint8_t out[32]) {
  return bootutil_sha_finish((bootutil_sha_context*)ctx, out) ? -EIO : 0;
}

static int s1_sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
  bootutil_sha_context c;
  int rc = bootutil_sha_init(&c);

  if (rc == 0) {
    rc = bootutil_sha_update(&c, in, len);
  }
  if (rc == 0) {
    rc = bootutil_sha_finish(&c, out);
  }
  bootutil_sha_drop(&c);
  return rc ? -EIO : 0;
}

/* ---- ECDSA-P256 verify ----
 * pub: DER SubjectPublicKeyInfo (imgtool getpub output).
 * sig: DER ECDSA-Sig-Value (the IMAGE_TLV_ECDSA_SIG bytes).
 * Reuses the bootutil crypto abstraction so the decode path matches what
 * image_validate.c does for a normally-managed image.
 */
static int s1_ecdsa_p256_verify(const uint8_t hash[32], const uint8_t* sig,
                                size_t sig_len, const uint8_t* pub,
                                size_t pub_len) {
  bootutil_ecdsa_context ctx;
  uint8_t* cp = (uint8_t*)pub;
  uint8_t* end = cp + pub_len;
  int rc;

  bootutil_ecdsa_init(&ctx);

  /* Advances cp to the raw EC point inside the SPKI. */
  rc = bootutil_ecdsa_parse_public_key(&ctx, &cp, end);
  if (rc != 0) {
    bootutil_ecdsa_drop(&ctx);
    return -EINVAL;
  }

  rc = bootutil_ecdsa_verify(&ctx, cp, (size_t)(end - cp), (uint8_t*)hash,
                             BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE, (uint8_t*)sig,
                             sig_len);
  bootutil_ecdsa_drop(&ctx);
  return rc ? -EBADMSG : 0;
}

/* ---- swap / resume (MECHANISM ONLY - no signature check) ----
 *
 * A self-contained, power-loss-resumable MCUBOOT_SWAP_USING_OFFSET exchange
 * over one primary/secondary slot pair, addressed by device-relative byte
 * offsets (not flash_area IDs - Stage 1 and the caller have divergent
 * devicetrees). Progress is journaled in the secondary slot's own trailer
 * sector, which the body loop never touches; on re-entry the journal says
 * which sector to resume from. Caller runs single-threaded in bootloader
 * context; signature validation is the caller's job, before and after.
 */

#define SWAP_STAT_MAGIC 0x53575031u /* "SWP1" */

/* Written once per fresh swap at the base of the secondary trailer sector
 * (sec_off + pri_size). */
struct swap_stat_hdr {
  uint32_t magic;
  uint32_t pri_off;
  uint32_t pri_size;
  uint32_t sec_off;
  uint32_t sec_size;
  uint32_t sector_size;
  uint32_t iterations; /* pri_size/sector_size - 1 */
  uint32_t flags;
  uint32_t crc; /* crc32_ieee over the 32 preceding bytes */
  uint32_t _pad[3];
};

/* Appended, one atomic write-block immediately before each iteration's
 * first flash op. idx is the logical iteration; entries are packed by
 * append order (slot), so a resumed run re-appends into fresh slots. */
struct swap_stat_entry {
  uint16_t idx;
  uint16_t idx_not; /* ~idx - rejects erased 0xFF fill */
  uint32_t seq;     /* 1-based, monotonic */
  uint32_t crc;     /* crc32_ieee over idx|idx_not|seq (8 bytes) */
  uint32_t _pad;
};

BUILD_ASSERT(sizeof(struct swap_stat_hdr) % 16 == 0, "hdr not 16B aligned");
BUILD_ASSERT(sizeof(struct swap_stat_entry) == 16, "entry must be one quadword");

/* Validate offset-mode geometry; returns the sector size, or 0 on failure. */
static uint32_t _swap_geometry(uint32_t pri_off, uint32_t pri_size,
                               uint32_t sec_off, uint32_t sec_size) {
  if (sec_size <= pri_size) {
    return 0;
  }
  uint32_t sector = sec_size - pri_size; /* offset-mode: exactly one sector */
  if ((sector & (sector - 1)) != 0 || pri_size == 0 ||
      (pri_size % sector) != 0 || (pri_off % sector) != 0 ||
      (sec_off % sector) != 0) {
    return 0;
  }
  return sector;
}

/* Erase dst sector, then copy sector_size bytes src->dst through buf. All
 * flash I/O goes through the caller-supplied ops: this code runs in the
 * caller's context (Stage 1's own flash-driver RAM state is dead after the
 * jump), so it must not touch the Zephyr flash driver directly. */
static int _swap_copy_sector(const struct stage1_flash_ops* ops, uint32_t src,
                             uint32_t dst, uint32_t sector_size, uint8_t* buf,
                             uint32_t chunk) {
  int rc = ops->erase(dst, sector_size);
  if (rc) {
    return rc;
  }
  for (uint32_t o = 0; o < sector_size; o += chunk) {
    rc = ops->read(src + o, buf, chunk);
    if (rc) {
      return rc;
    }
    rc = ops->write(dst + o, buf, chunk);
    if (rc) {
      return rc;
    }
  }
  return 0;
}

static bool _swap_hdr_valid(const struct swap_stat_hdr* h, uint32_t pri_off,
                            uint32_t pri_size, uint32_t sec_off,
                            uint32_t sec_size) {
  return h->magic == SWAP_STAT_MAGIC &&
         crc32_ieee((const uint8_t*)h, offsetof(struct swap_stat_hdr, crc)) ==
             h->crc &&
         h->pri_off == pri_off && h->pri_size == pri_size &&
         h->sec_off == sec_off && h->sec_size == sec_size;
}

/* Walk the appended entries. out_resume = highest recorded idx (restart
 * there), out_slot = number of valid entries (next append slot), out_seq =
 * next seq. */
static void _swap_scan_log(const struct stage1_flash_ops* ops, uint32_t log_base,
                           uint32_t log_limit, uint32_t* out_resume,
                           uint32_t* out_slot, uint32_t* out_seq) {
  uint32_t off = log_base + sizeof(struct swap_stat_hdr);
  uint32_t slot = 0, resume = 0, seq = 1;
  bool found = false;

  while (off + sizeof(struct swap_stat_entry) <= log_limit) {
    struct swap_stat_entry e;
    if (ops->read(off, &e, sizeof(e)) != 0) {
      break;
    }
    if (e.idx == 0xFFFFu && e.idx_not == 0xFFFFu) {
      break; /* erased tail */
    }
    if ((uint16_t)~e.idx != e.idx_not ||
        crc32_ieee((const uint8_t*)&e, 8) != e.crc) {
      break;
    }
    if (!found || e.idx >= resume) {
      resume = e.idx;
    }
    if (e.seq >= seq) {
      seq = e.seq + 1;
    }
    found = true;
    slot++;
    off += sizeof(struct swap_stat_entry);
  }
  *out_resume = resume;
  *out_slot = slot;
  *out_seq = seq;
}

static bool _ops_ok(const struct stage1_flash_ops* ops) {
  return ops && ops->read && ops->write && ops->erase;
}

static int s1_swap_state(const struct stage1_flash_ops* ops, uint32_t pri_off,
                         uint32_t pri_size, uint32_t sec_off,
                         uint32_t sec_size) {
  if (!_ops_ok(ops) ||
      _swap_geometry(pri_off, pri_size, sec_off, sec_size) == 0) {
    return -EINVAL;
  }
  struct swap_stat_hdr h;
  int ret = ops->read(sec_off + pri_size, &h, sizeof(h));
  if (ret != 0) {
    return ret;
  }
  /* PENDING (secondary marked but swap not started) is left for the caller's
   * boot_swap_type() to detect - this reports only an interrupted swap. */
  return _swap_hdr_valid(&h, pri_off, pri_size, sec_off, sec_size)
             ? STAGE1_SWAP_IN_PROGRESS
             : STAGE1_SWAP_NONE;
}

/* Rewrite the primary slot's MCUboot trailer after the exchange: erase its
 * trailer sector, then write magic (+ image_ok for a permanent swap).
 * boot_swap_type() then reads primary magic=GOOD with erased flags and an
 * unset secondary -> BOOT_SWAP_TYPE_NONE, so the new image boots and the
 * app confirms it. Offsets follow bootutil_misc.h; BOOT_IMG_MAGIC is
 * const (.rodata) so it survives the jump. */
static int _swap_write_primary_trailer(const struct stage1_flash_ops* ops,
                                       uint32_t pri_off, uint32_t pri_size,
                                       uint32_t sector, uint32_t flags) {
  int rc = ops->erase(pri_off + pri_size - sector, sector);
  if (rc) {
    return rc;
  }
  rc = ops->write(pri_off + pri_size - BOOT_MAGIC_SZ, BOOT_IMG_MAGIC,
                  BOOT_MAGIC_SZ);
  if (rc) {
    return rc;
  }
  if (flags & STAGE1_SWAP_F_PERMANENT) {
    uint8_t ok[BOOT_MAX_ALIGN];
    uint32_t ok_off =
        ALIGN_DOWN((pri_size - BOOT_MAGIC_SZ) - BOOT_MAX_ALIGN, BOOT_MAX_ALIGN);
    memset(ok, 0xff, sizeof(ok));
    ok[0] = 0x01; /* BOOT_FLAG_SET */
    rc = ops->write(pri_off + ok_off, ok, BOOT_MAX_ALIGN);
    if (rc) {
      return rc;
    }
  }
  return 0;
}

static int s1_swap_run(const struct stage1_flash_ops* ops, uint32_t pri_off,
                       uint32_t pri_size, uint32_t sec_off, uint32_t sec_size,
                       uint32_t flags, void* scratch, size_t scratch_len,
                       struct image_header* primary_hdr_out) {
  uint32_t sector = _swap_geometry(pri_off, pri_size, sec_off, sec_size);
  if (!_ops_ok(ops) || sector == 0 || scratch == NULL) {
    return -EINVAL;
  }

  /* Copy chunk: largest power of two <= min(scratch_len, 2048) that divides
   * the sector and is >= the 16-byte write block. */
  uint32_t chunk = 2048;
  while (chunk > scratch_len || (sector % chunk) != 0) {
    chunk >>= 1;
    if (chunk < 16) {
      return -ENOMEM;
    }
  }
  uint8_t* buf = scratch;

  const uint32_t iterations = (pri_size / sector) - 1;
  const uint32_t log_base = sec_off + pri_size;
  const uint32_t log_limit = sec_off + sec_size;

  struct swap_stat_hdr h;
  int rc = ops->read(log_base, &h, sizeof(h));
  if (rc) {
    return -EIO;
  }

  uint32_t start_idx, slot, seq;
  if (_swap_hdr_valid(&h, pri_off, pri_size, sec_off, sec_size)) {
    _swap_scan_log(ops, log_base, log_limit, &start_idx, &slot, &seq);
    BOOT_LOG_WRN("stage1 swap: resume at sector %u/%u", start_idx, iterations);
  } else {
    rc = ops->erase(log_base, sector); /* clears any stale trailer too */
    if (rc) {
      return rc;
    }
    memset(&h, 0, sizeof(h));
    h.magic = SWAP_STAT_MAGIC;
    h.pri_off = pri_off;
    h.pri_size = pri_size;
    h.sec_off = sec_off;
    h.sec_size = sec_size;
    h.sector_size = sector;
    h.iterations = iterations;
    h.flags = flags;
    h.crc = crc32_ieee((const uint8_t*)&h, offsetof(struct swap_stat_hdr, crc));
    rc = ops->write(log_base, &h, sizeof(h));
    if (rc) {
      return rc;
    }
    start_idx = 0;
    slot = 0;
    seq = 1;
  }

  for (uint32_t idx = start_idx; idx < iterations; idx++) {
    uint32_t eoff = log_base + sizeof(struct swap_stat_hdr) +
                    slot * sizeof(struct swap_stat_entry);
    if (eoff + sizeof(struct swap_stat_entry) > log_limit) {
      BOOT_LOG_ERR("stage1 swap: status log full");
      return -ENOSPC;
    }
    struct swap_stat_entry e = {0};
    e.idx = (uint16_t)idx;
    e.idx_not = (uint16_t)~idx;
    e.seq = seq++;
    e.crc = crc32_ieee((const uint8_t*)&e, 8);
    rc = ops->write(eoff, &e, sizeof(e)); /* one atomic quadword */
    if (rc) {
      return rc;
    }
    slot++;

    /* step 1: sec[idx] <- pri[idx]  (preserve the outgoing primary sector) */
    rc = _swap_copy_sector(ops, pri_off + idx * sector, sec_off + idx * sector,
                           sector, buf, chunk);
    if (rc) {
      return rc;
    }
    /* step 2: pri[idx] <- sec[idx+1] (candidate sector, shifted by one) */
    rc = _swap_copy_sector(ops, sec_off + (idx + 1) * sector,
                           pri_off + idx * sector, sector, buf, chunk);
    if (rc) {
      return rc;
    }
  }

  rc = _swap_write_primary_trailer(ops, pri_off, pri_size, sector, flags);
  if (rc) {
    BOOT_LOG_ERR("stage1 swap: primary trailer write failed (%d)", rc);
    return rc;
  }

  /* Secondary trailer: erase - clears the journal and the now-stale
   * outgoing-image trailer so the swap cannot re-fire. */
  rc = ops->erase(log_base, sector);
  if (rc) {
    return rc;
  }

  if (primary_hdr_out) {
    if (ops->read(pri_off, primary_hdr_out, sizeof(*primary_hdr_out)) != 0) {
      return -EIO;
    }
  }
  BOOT_LOG_INF("stage1 swap: complete (%u sectors)", iterations);
  return 0;
}

/* ---- the table ---- */

const struct stage1_services_api stage1_services_api_table
    __attribute__((used)) = {
        .magic = STAGE1_SVC_ABI_MAGIC,
        .version = STAGE1_SVC_ABI_VERSION,
        .struct_size = sizeof(struct stage1_services_api),
        .capabilities =
            STAGE1_CAP_SHA256 | STAGE1_CAP_ECDSA_P256 | STAGE1_CAP_SWAP_OFFSET,

        .sha256 = s1_sha256,
        .sha256_init = s1_sha256_init,
        .sha256_update = s1_sha256_update,
        .sha256_final = s1_sha256_final,
        .ecdsa_p256_verify = s1_ecdsa_p256_verify,

        .swap_state = s1_swap_state,
        .swap_run = s1_swap_run,
};

void stage1_services_publish(void) {
  struct stage1_services_tlv tlv = {
      .format_version = STAGE1_SVC_TLV_VERSION,
      .abi_magic = STAGE1_SVC_ABI_MAGIC,
      .abi_version = STAGE1_SVC_ABI_VERSION,
      .struct_size = sizeof(struct stage1_services_api),
      .table_addr = (uint32_t)(uintptr_t)&stage1_services_api_table,
  };
  int rc;

  tlv.table_crc = crc32_ieee((const uint8_t*)&stage1_services_api_table,
                             sizeof(stage1_services_api_table));
  /* Blucifer-TLV convention: trailing CRC over all preceding payload bytes,
   * matching sensc_boot's shared_data_read_checked(). */
  tlv.payload_crc = crc32_ieee(
      (const uint8_t*)&tlv, offsetof(struct stage1_services_tlv, payload_crc));

  rc = boot_add_data_to_shared_area(STAGE1_SVC_TLV_MAJOR, STAGE1_SVC_TLV_MINOR,
                                    sizeof(tlv), (const uint8_t*)&tlv);
  if (rc != 0) {
    BOOT_LOG_WRN("stage1 services: shared-area publish failed (%d)", rc);
  }
}
