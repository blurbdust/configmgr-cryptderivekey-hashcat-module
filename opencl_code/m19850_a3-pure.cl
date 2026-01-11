/**
 * Author......: Christopher Panayi, MWR CyberSec
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

//CryptDeriveKey is basically sha1hmac if the input is forced to be greater than 64.
//Based on the code from sha1_hmac_init and ipad from sha1_hmac_init_64.
//I only implement ipad calculation, because this allows for the generation of up to a max of 512bit symmetric keys.
DECLSPEC void crypt_derive_key_password_derivation (PRIVATE_AS u32 *aes_key, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha1_ctx_t tmp;

  sha1_init (&tmp);

  sha1_update_utf16le_swap (&tmp, w, len);

  sha1_final (&tmp);

  // Take first 20 bytes of SHA1 hash, pad to 64 bytes with zeros
  w0[0] = tmp.h[0];
  w0[1] = tmp.h[1];
  w0[2] = tmp.h[2];
  w0[3] = tmp.h[3];
  w1[0] = tmp.h[4];
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  // ipad - XOR with 0x36363636
  t0[0] = w0[0] ^ 0x36363636;
  t0[1] = w0[1] ^ 0x36363636;
  t0[2] = w0[2] ^ 0x36363636;
  t0[3] = w0[3] ^ 0x36363636;
  t1[0] = w1[0] ^ 0x36363636;
  t1[1] = w1[1] ^ 0x36363636;
  t1[2] = w1[2] ^ 0x36363636;
  t1[3] = w1[3] ^ 0x36363636;
  t2[0] = w2[0] ^ 0x36363636;
  t2[1] = w2[1] ^ 0x36363636;
  t2[2] = w2[2] ^ 0x36363636;
  t2[3] = w2[3] ^ 0x36363636;
  t3[0] = w3[0] ^ 0x36363636;
  t3[1] = w3[1] ^ 0x36363636;
  t3[2] = w3[2] ^ 0x36363636;
  t3[3] = w3[3] ^ 0x36363636;

  sha1_ctx_t ipad_ctx;

  sha1_init (&ipad_ctx);

  sha1_update_64 (&ipad_ctx, t0, t1, t2, t3, 64);

  sha1_final (&ipad_ctx);

  // Extract first 128 bits (16 bytes) for AES-128 key
  aes_key[0] = ipad_ctx.h[0];
  aes_key[1] = ipad_ctx.h[1];
  aes_key[2] = ipad_ctx.h[2];
  aes_key[3] = ipad_ctx.h[3];
}

KERNEL_FQ KERNEL_FA void m19850_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    // Derive AES key from password
    u32 aes_key[4];

    crypt_derive_key_password_derivation (aes_key, w, pw_len);

    u32 aes_ks[44];
    u32 encrypted_block[4];

    AES128_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3);

    // UTF-16LE "<?xml ve" (8 chars = 16 bytes = 1 AES block)
    const u32 enc_blocks[4] = { 0x3c003f00, 0x78006d00, 0x6c002000, 0x76006500 };

    AES128_encrypt (aes_ks, enc_blocks, encrypted_block, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = encrypted_block[DGST_R0];
    const u32 r1 = encrypted_block[DGST_R1];
    const u32 r2 = encrypted_block[DGST_R2];
    const u32 r3 = encrypted_block[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m19850_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    // Derive AES key from password
    u32 aes_key[4];

    crypt_derive_key_password_derivation (aes_key, w, pw_len);

    u32 aes_ks[44];
    u32 encrypted_block[4];

    AES128_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3);

    // UTF-16LE "<?xml ve" (8 chars = 16 bytes = 1 AES block)
    const u32 enc_blocks[4] = { 0x3c003f00, 0x78006d00, 0x6c002000, 0x76006500 };

    AES128_encrypt (aes_ks, enc_blocks, encrypted_block, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = encrypted_block[DGST_R0];
    const u32 r1 = encrypted_block[DGST_R1];
    const u32 r2 = encrypted_block[DGST_R2];
    const u32 r3 = encrypted_block[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
