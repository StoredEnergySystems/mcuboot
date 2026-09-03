/*
 * Copyright: 2026 Stored Energy Systems - All Rights Reserved
 *
 * License: Proprietary and confidential
 * Unauthorized use of this file, via any medium is strictly prohibited.
 *
 * Stage 1 (MCUboot) services API - ABI contract.
 *
 * Owned by the MCUboot fork (Stage 1 defines and freezes this interface).
 * Lives on boot/zephyr/include, so both the fork's stage1_services_api.c and
 * the consuming sensc_dfu module / apps pick it up via the
 * boot/zephyr/include path they already carry - no second copy.
 *
 * Mechanism: Stage 1 keeps a `const struct stage1_services_api` in its
 * immutable flash .rodata and publishes a locator (address + CRC + mirrored
 * magic/version) into the bl_shared_data retained-RAM TLV area under
 * TLV_MAJOR_BLUCIFER / TLV_CRYPTO_CAPS just before jumping. Consumers read
 * the locator with shared_data_read_checked(), validate it hard (magic ->
 * range -> struct magic -> table CRC), then call through the pointers.
 *
 * Rules for every exported function (frozen for the life of the immutable
 * Stage 1 image):
 *  - Stateless one-shots, or streaming with a CALLER-owned context/scratch.
 *    Stage 1 keeps no state between calls; its .data/.bss is the caller's
 *    RAM after the jump.
 *  - CMSE-clean signatures: fixed-width scalars, pointers, explicit lengths.
 *    No by-value struct/float args or returns. A future TrustZone Stage 1
 *    fills the same table with NSC veneer addresses; callers do not change.
 *  - Return 0 on success, negative errno on failure.
 */
#ifndef STAGE1_SERVICES_API_H_
#define STAGE1_SERVICES_API_H_

#include <stddef.h>
#include <stdint.h>

#include <bootutil/image.h> /* struct image_header */

#ifdef __cplusplus
extern "C" {
#endif

#define STAGE1_SVC_ABI_MAGIC   0x53315356u /* "S1SV" */
#define STAGE1_SVC_ABI_VERSION 1u

/* TLV coordinates of the locator in the bl_shared_data area. Mirror of
 * TLV_MAJOR_BLUCIFER / TLV_CRYPTO_CAPS in the sensc_boot module - defined
 * here too so the MCUboot fork needs only this header. */
#define STAGE1_SVC_TLV_MAJOR 0x3u
#define STAGE1_SVC_TLV_MINOR 0x3u

/* capabilities bitmask */
#define STAGE1_CAP_SHA256      (1u << 0)
#define STAGE1_CAP_ECDSA_P256  (1u << 1)
#define STAGE1_CAP_SWAP_OFFSET (1u << 2)

/* Caller-owned SHA-256 streaming context. Opaque; sized generously so the
 * Stage 1 implementation's real context fits with margin. 8-byte aligned so
 * it can back any backend's context struct. Stage 1 BUILD_ASSERTs its actual
 * sizeof against this. */
#define STAGE1_SHA256_CTX_WORDS 32
struct stage1_sha256_ctx {
  uint32_t opaque[STAGE1_SHA256_CTX_WORDS];
} __attribute__((aligned(8)));

/* Caller-owned scratch for swap_run() - used as the sector copy buffer
 * (the swap is streamed in chunks, so a full sector is not required).
 * swap_run() takes the largest power-of-two chunk <= min(scratch_len, 2048)
 * that divides the sector and is >= the flash write block; -ENOMEM if none
 * fits (i.e. scratch_len < 16). */
#define STAGE1_SWAP_SCRATCH_BYTES 2048

enum stage1_swap_state {
  STAGE1_SWAP_NONE = 0,        /* no pending or interrupted swap */
  STAGE1_SWAP_PENDING = 1,     /* secondary marked, swap not started */
  STAGE1_SWAP_IN_PROGRESS = 2, /* interrupted swap - resume needed */
};

/* swap_run() flags */
#define STAGE1_SWAP_F_PERMANENT (1u << 0) /* also write image_ok=SET on primary */

/* Caller-supplied flash I/O for swap_state()/swap_run(). REQUIRED: the swap
 * runs in the caller's context after the jump, where Stage 1's own flash
 * driver (device struct, mutex, lazy page-layout cache) is dead RAM. The
 * caller passes thin wrappers over its live flash driver. Offsets are
 * device-relative bytes (same space as pri_off/sec_off). erase offset/len
 * must be sector-aligned; write offset/len must be write-block-aligned.
 * Each returns 0 or a negative errno. */
struct stage1_flash_ops {
  int (*read)(uint32_t off, void *dst, uint32_t len);
  int (*write)(uint32_t off, const void *src, uint32_t len);
  int (*erase)(uint32_t off, uint32_t len);
};

struct stage1_services_api {
  uint32_t magic;        /* STAGE1_SVC_ABI_MAGIC */
  uint16_t version;      /* STAGE1_SVC_ABI_VERSION */
  uint16_t struct_size;  /* sizeof(struct stage1_services_api) */
  uint32_t capabilities; /* STAGE1_CAP_* */

  /* ---- crypto: stateless one-shot / caller-owned streaming ctx ---- */
  int (*sha256)(const uint8_t *in, size_t len, uint8_t out[32]);
  int (*sha256_init)(struct stage1_sha256_ctx *ctx);
  int (*sha256_update)(struct stage1_sha256_ctx *ctx, const uint8_t *in,
                       size_t len);
  int (*sha256_final)(struct stage1_sha256_ctx *ctx, uint8_t out[32]);
  int (*ecdsa_p256_verify)(const uint8_t hash[32], const uint8_t *sig,
                           size_t sig_len, const uint8_t *pub, size_t pub_len);

  /* ---- swap / resume: MECHANISM ONLY, no signature check ----
   * Bootloader context only (caller runs single-threaded, pre-jump, with no
   * concurrent flash users). All flash I/O goes through the caller-supplied
   * `ops` (see struct stage1_flash_ops). Offsets/sizes are device-relative
   * byte ranges - pass PARTITION_OFFSET()/PARTITION_SIZE() of the primary
   * and secondary slots. secondary_size must equal primary_size + one flash
   * sector (MCUBOOT_SWAP_USING_OFFSET sizing); mismatches return -EINVAL.
   * swap_run() rewrites the primary slot's MCUboot trailer (magic, +image_ok
   * if STAGE1_SWAP_F_PERMANENT) itself via ops; the caller's boot_swap_type()
   * then reads NONE and the app confirms the new image. */
  int (*swap_state)(const struct stage1_flash_ops *ops, uint32_t pri_off,
                    uint32_t pri_size, uint32_t sec_off,
                    uint32_t sec_size); /* -> enum stage1_swap_state / -errno */
  int (*swap_run)(const struct stage1_flash_ops *ops, uint32_t pri_off,
                  uint32_t pri_size, uint32_t sec_off, uint32_t sec_size,
                  uint32_t flags, void *scratch, size_t scratch_len,
                  struct image_header *primary_hdr_out);

  uint32_t reserved[8]; /* zero-filled; additive growth without breaking old readers */
};

#define STAGE1_SVC_TLV_VERSION 1u

/* Locator TLV payload: minor = TLV_CRYPTO_CAPS (0x03) under
 * TLV_MAJOR_BLUCIFER. Trailing payload_crc is the Blucifer-TLV convention
 * (crc32_ieee over all preceding payload bytes), verified by
 * shared_data_read_checked(). */
struct stage1_services_tlv {
  uint8_t format_version; /* STAGE1_SVC_TLV_VERSION */
  uint8_t _pad[3];
  uint32_t abi_magic;   /* mirror of struct .magic */
  uint16_t abi_version; /* mirror of struct .version */
  uint16_t struct_size; /* mirror of struct .struct_size */
  uint32_t table_addr;  /* address of the const struct in Stage 1 flash */
  uint32_t table_crc;   /* crc32_ieee over struct_size bytes at table_addr */
  uint32_t payload_crc; /* crc32_ieee over the 20 preceding bytes */
};

#ifdef __cplusplus
}
#endif
#endif /* STAGE1_SERVICES_API_H_ */
