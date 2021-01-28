/*
 * Copyright (C) 2020, Emmanuel Fleury <emmanuel.fleury@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef AES128_H
#define AES128_H

#include <stdint.h> /* uint8_t */

#include <wmmintrin.h> /* AES-NI intrinsics */

/* Compile with: gcc -march=native -msse -msse2 -maes */

static inline __m128i
aes128_key_expansion (__m128i key, __m128i keygened)
{
  keygened = _mm_shuffle_epi32 (keygened, _MM_SHUFFLE (0x3, 0x3, 0x3, 0x3));
  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 0x4));
  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 0x4));
  key = _mm_xor_si128 (key, _mm_slli_si128 (key, 0x4));
  return _mm_xor_si128 (key, keygened);
}

#define AES_128_key_exp(k, rcon)                                               \
  aes128_key_expansion (k, _mm_aeskeygenassist_si128 (k, rcon))

static inline void
aes128_load_key_encrypt_only (uint8_t *key, __m128i *key_schedule)
{
  key_schedule[0] = _mm_loadu_si128 ((const __m128i *) key);
  key_schedule[1] = AES_128_key_exp (key_schedule[0], 0x01);
  key_schedule[2] = AES_128_key_exp (key_schedule[1], 0x02);
  key_schedule[3] = AES_128_key_exp (key_schedule[2], 0x04);
  key_schedule[4] = AES_128_key_exp (key_schedule[3], 0x08);
  key_schedule[5] = AES_128_key_exp (key_schedule[4], 0x10);
  key_schedule[6] = AES_128_key_exp (key_schedule[5], 0x20);
  key_schedule[7] = AES_128_key_exp (key_schedule[6], 0x40);
  key_schedule[8] = AES_128_key_exp (key_schedule[7], 0x80);
  key_schedule[9] = AES_128_key_exp (key_schedule[8], 0x1b);
  key_schedule[10] = AES_128_key_exp (key_schedule[9], 0x36);
}

static inline void
aes128_load_key (uint8_t *key, __m128i *key_schedule)
{
  aes128_load_key_encrypt_only (key, key_schedule);

  /* Generate decryption keys in reverse order:
   * - k[0] is shared by first encryption round and last decryption
   *   round (and is the original user key).
   * - k[10] is shared by last encryption and first decryption rounds.
   */
  key_schedule[11] = _mm_aesimc_si128 (key_schedule[9]);
  key_schedule[12] = _mm_aesimc_si128 (key_schedule[8]);
  key_schedule[13] = _mm_aesimc_si128 (key_schedule[7]);
  key_schedule[14] = _mm_aesimc_si128 (key_schedule[6]);
  key_schedule[15] = _mm_aesimc_si128 (key_schedule[5]);
  key_schedule[16] = _mm_aesimc_si128 (key_schedule[4]);
  key_schedule[17] = _mm_aesimc_si128 (key_schedule[3]);
  key_schedule[18] = _mm_aesimc_si128 (key_schedule[2]);
  key_schedule[19] = _mm_aesimc_si128 (key_schedule[1]);
}

static inline void
aes128_encrypt (__m128i *key_schedule, uint8_t *plain, uint8_t *cipher)
{
  __m128i m = _mm_loadu_si128 ((__m128i *) plain);

  /* First round (key whitening) */
  m = _mm_xor_si128 (m, key_schedule[0]);

  /* Inner encryption rounds */
  m = _mm_aesenc_si128 (m, key_schedule[1]);
  m = _mm_aesenc_si128 (m, key_schedule[2]);
  m = _mm_aesenc_si128 (m, key_schedule[3]);
  m = _mm_aesenc_si128 (m, key_schedule[4]);
  m = _mm_aesenc_si128 (m, key_schedule[5]);
  m = _mm_aesenc_si128 (m, key_schedule[6]);
  m = _mm_aesenc_si128 (m, key_schedule[7]);
  m = _mm_aesenc_si128 (m, key_schedule[8]);
  m = _mm_aesenc_si128 (m, key_schedule[9]);

  /* Last encryption round */
  m = _mm_aesenclast_si128 (m, key_schedule[10]);

  _mm_storeu_si128 ((__m128i *) cipher, m);
}

static inline void
aes128_decrypt (__m128i *key_schedule, uint8_t *cipher, uint8_t *plain)
{
  __m128i m = _mm_loadu_si128 ((__m128i *) cipher);

  /* First round (key whitening) */
  m = _mm_xor_si128 (m, key_schedule[10 + 0]);

  /* Inner decryption rounds */
  m = _mm_aesdec_si128 (m, key_schedule[10 + 1]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 2]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 3]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 4]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 5]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 6]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 7]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 8]);
  m = _mm_aesdec_si128 (m, key_schedule[10 + 9]);

  /* Last decryption round */
  m = _mm_aesdeclast_si128 (m, key_schedule[0]);

  _mm_storeu_si128 ((__m128i *) plain, m);
}

#endif /* AES128_H */
