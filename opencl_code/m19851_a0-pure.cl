/**
 * Author......: Christopher Panayi, MWR CyberSec
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#endif

DECLSPEC void crypt_derive_key_password_derivation (sha1_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha1_ctx_t tmp;

  sha1_init (&tmp);

  sha1_update_utf16le_swap (&tmp, w, len);

  sha1_final (&tmp);

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

  // ipad

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

  sha1_init (&ctx->ipad);

  sha1_update_64 (&ctx->ipad, t0, t1, t2, t3, 64);

  sha1_final(&ctx->ipad);
}

DECLSPEC void crypt_derive_key_password_derivation2 (sha1_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  sha1_ctx_vector_t tmp;

  sha1_init_vector (&tmp);

  sha1_update_vector_utf16le_swap (&tmp, w, len);

  sha1_final_vector (&tmp);

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

  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];

  // ipad

  t0[0] = w0[0] ^ 0x5c5c5c5c;
  t0[1] = w0[1] ^ 0x5c5c5c5c;
  t0[2] = w0[2] ^ 0x5c5c5c5c;
  t0[3] = w0[3] ^ 0x5c5c5c5c;
  t1[0] = w1[0] ^ 0x5c5c5c5c;
  t1[1] = w1[1] ^ 0x5c5c5c5c;
  t1[2] = w1[2] ^ 0x5c5c5c5c;
  t1[3] = w1[3] ^ 0x5c5c5c5c;
  t2[0] = w2[0] ^ 0x5c5c5c5c;
  t2[1] = w2[1] ^ 0x5c5c5c5c;
  t2[2] = w2[2] ^ 0x5c5c5c5c;
  t2[3] = w2[3] ^ 0x5c5c5c5c;
  t3[0] = w3[0] ^ 0x5c5c5c5c;
  t3[1] = w3[1] ^ 0x5c5c5c5c;
  t3[2] = w3[2] ^ 0x5c5c5c5c;
  t3[3] = w3[3] ^ 0x5c5c5c5c;

  sha1_init_vector (&ctx->ipad);

  sha1_update_vector_64 (&ctx->ipad, t0, t1, t2, t3, 64);

  sha1_final_vector (&ctx->ipad);
}

KERNEL_FQ void m19851_mxx (KERN_ATTR_RULES())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  COPY_PW (pws[gid]);
  
  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW; 
    
    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_hmac_ctx_t sha1_hmac_ctx;
    crypt_derive_key_password_derivation(&sha1_hmac_ctx, tmp.i,tmp.pw_len);
    sha1_hmac_ctx_t sha1_hmac_ctx2;
    crypt_derive_key_password_derivation2(&sha1_hmac_ctx2, tmp.i,tmp.pw_len);
    
    u32 aes_key[8];

    aes_key[0] = sha1_hmac_ctx.ipad.h[0];
    aes_key[1] = sha1_hmac_ctx.ipad.h[1];
    aes_key[2] = sha1_hmac_ctx.ipad.h[2];
    aes_key[3] = sha1_hmac_ctx.ipad.h[3];
    aes_key[4] = sha1_hmac_ctx.ipad.h[4];
    aes_key[5] = sha1_hmac_ctx2.ipad.h[0];
    aes_key[6] = sha1_hmac_ctx2.ipad.h[1];
    aes_key[7] = sha1_hmac_ctx2.ipad.h[2];

    u32 aes_cbc_encrypt_xml_ks[60];
    u32 encrypted_block[4];

    AES256_set_encrypt_key (aes_cbc_encrypt_xml_ks, aes_key, s_te0, s_te1, s_te2, s_te3);

    const u32 enc_blocks [4] = {1006649088U,2013293824U,1811947520U,1979737344U}; // UTF-16LE "<?xm" represented in unsigned int

    AES256_encrypt (aes_cbc_encrypt_xml_ks, enc_blocks, encrypted_block, s_te0, s_te1, s_te2, s_te3,s_te4);

    const u32 r0 = encrypted_block[DGST_R0];
    const u32 r1 = encrypted_block[DGST_R1];
    const u32 r2 = encrypted_block[DGST_R2];
    const u32 r3 = encrypted_block[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m19851_sxx (KERN_ATTR_RULES())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_hmac_ctx_t sha1_hmac_ctx;
    crypt_derive_key_password_derivation(&sha1_hmac_ctx, tmp.i,tmp.pw_len);
    sha1_hmac_ctx_t sha1_hmac_ctx2;
    crypt_derive_key_password_derivation2(&sha1_hmac_ctx2, tmp.i,tmp.pw_len);
    
    u32 aes_key[8];

    aes_key[0] = sha1_hmac_ctx.ipad.h[0];
    aes_key[1] = sha1_hmac_ctx.ipad.h[1];
    aes_key[2] = sha1_hmac_ctx.ipad.h[2];
    aes_key[3] = sha1_hmac_ctx.ipad.h[3];
    aes_key[4] = sha1_hmac_ctx.ipad.h[4];
    aes_key[5] = sha1_hmac_ctx2.ipad.h[0];
    aes_key[6] = sha1_hmac_ctx2.ipad.h[1];
    aes_key[7] = sha1_hmac_ctx2.ipad.h[2];

    u32 aes_cbc_encrypt_xml_ks[60];
    u32 encrypted_block[4];

    AES256_set_encrypt_key (aes_cbc_encrypt_xml_ks, aes_key, s_te0, s_te1, s_te2, s_te3);

    const u32 enc_blocks [4] = {1006649088U,2013293824U,1811947520U,1979737344U}; // UTF-16LE "<?xm" represented in unsigned int

    AES256_encrypt (aes_cbc_encrypt_xml_ks, enc_blocks, encrypted_block, s_te0, s_te1, s_te2, s_te3,s_te4);

    const u32 r0 = encrypted_block[DGST_R0];
    const u32 r1 = encrypted_block[DGST_R1];
    const u32 r2 = encrypted_block[DGST_R2];
    const u32 r3 = encrypted_block[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
