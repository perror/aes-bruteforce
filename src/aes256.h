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

#ifndef AES256_H
#define AES256_H

#include <stdint.h> /* uint8_t */

#include <wmmintrin.h> /* AES-NI intrinsics */

/* Compile with: gcc -march=native -msse -msse2 -maes */

static inline void
KEY_256_ASSIST_1 (__m128i *temp1, __m128i *temp2)
{
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32 (*temp2, 0xff);
  temp4 = _mm_slli_si128 (*temp1, 0x4);
  *temp1 = _mm_xor_si128 (*temp1, temp4);
  temp4 = _mm_slli_si128 (temp4, 0x4);
  *temp1 = _mm_xor_si128 (*temp1, temp4);
  temp4 = _mm_slli_si128 (temp4, 0x4);
  *temp1 = _mm_xor_si128 (*temp1, temp4);
  *temp1 = _mm_xor_si128 (*temp1, *temp2);
}

static void
KEY_256_ASSIST_2 (__m128i *temp1, __m128i *temp3)
{
  __m128i temp2, temp4;
  temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
  temp2 = _mm_shuffle_epi32 (temp4, 0xaa);
  temp4 = _mm_slli_si128 (*temp3, 0x4);
  *temp3 = _mm_xor_si128 (*temp3, temp4);
  temp4 = _mm_slli_si128 (temp4, 0x4);
  *temp3 = _mm_xor_si128 (*temp3, temp4);
  temp4 = _mm_slli_si128 (temp4, 0x4);
  *temp3 = _mm_xor_si128 (*temp3, temp4);
  *temp3 = _mm_xor_si128 (*temp3, temp2);
}

static inline void
aes256_load_key_encrypt_only (uint8_t *key, __m128i *key_schedule)
{
  __m128i temp1, temp2, temp3;
  temp1 = _mm_loadu_si128 ((__m128i *) key);
  temp3 = _mm_loadu_si128 ((__m128i *) (key + 16));
  key_schedule[0] = temp1;
  key_schedule[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128 (temp3, 0x01);
  KEY_256_ASSIST_1 (&temp1, &temp2);
  key_schedule[2] = temp1;
  KEY_256_ASSIST_2 (&temp1, &temp3);
  key_schedule[3] = temp3;
  temp2 = _mm_aeskeygenassist_si128 (temp3, 0x02);
  KEY_256_ASSIST_1 (&temp1, &temp2);
  key_schedule[4] = temp1;
  KEY_256_ASSIST_2 (&temp1, &temp3);
  key_schedule[5] = temp3;
  temp2 = _mm_aeskeygenassist_si128 (temp3, 0x04);
  KEY_256_ASSIST_1 (&temp1, &temp2);
  key_schedule[6] = temp1;
  KEY_256_ASSIST_2 (&temp1, &temp3);
  key_schedule[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128 (temp3, 0x08);
  KEY_256_ASSIST_1 (&temp1, &temp2);
  key_schedule[8] = temp1;
  KEY_256_ASSIST_2 (&temp1, &temp3);
  key_schedule[9] = temp3;
  temp2 = _mm_aeskeygenassist_si128 (temp3, 0x10);
  KEY_256_ASSIST_1 (&temp1, &temp2);
  key_schedule[10] = temp1;
  KEY_256_ASSIST_2 (&temp1, &temp3);
  key_schedule[11] = temp3;
  temp2 = _mm_aeskeygenassist_si128 (temp3, 0x20);
  KEY_256_ASSIST_1 (&temp1, &temp2);
  key_schedule[12] = temp1;
  KEY_256_ASSIST_2 (&temp1, &temp3);
  key_schedule[13] = temp3;
  temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
  KEY_256_ASSIST_1 (&temp1, &temp2);
  key_schedule[14] = temp1;
}

static inline void
aes256_load_key (uint8_t *key, __m128i *key_schedule)
{
  aes256_load_key_encrypt_only (key, key_schedule);

  key_schedule[15] = _mm_aesimc_si128 (key_schedule[13]);
  key_schedule[16] = _mm_aesimc_si128 (key_schedule[12]);
  key_schedule[17] = _mm_aesimc_si128 (key_schedule[11]);
  key_schedule[18] = _mm_aesimc_si128 (key_schedule[10]);
  key_schedule[19] = _mm_aesimc_si128 (key_schedule[9]);
  key_schedule[20] = _mm_aesimc_si128 (key_schedule[8]);
  key_schedule[21] = _mm_aesimc_si128 (key_schedule[7]);
  key_schedule[22] = _mm_aesimc_si128 (key_schedule[6]);
  key_schedule[23] = _mm_aesimc_si128 (key_schedule[5]);
  key_schedule[24] = _mm_aesimc_si128 (key_schedule[4]);
  key_schedule[25] = _mm_aesimc_si128 (key_schedule[3]);
  key_schedule[26] = _mm_aesimc_si128 (key_schedule[2]);
  key_schedule[27] = _mm_aesimc_si128 (key_schedule[1]);
}

static inline void
aes256_encrypt (__m128i *key_schedule, uint8_t *plain, uint8_t *cipher)
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
  m = _mm_aesenc_si128 (m, key_schedule[10]);
  m = _mm_aesenc_si128 (m, key_schedule[11]);
  m = _mm_aesenc_si128 (m, key_schedule[12]);
  m = _mm_aesenc_si128 (m, key_schedule[13]);

  /* Last encryption round */
  m = _mm_aesenclast_si128 (m, key_schedule[14]);

  _mm_storeu_si128 ((__m128i *) cipher, m);
}

static inline void
aes256_decrypt (__m128i *key_schedule, uint8_t *cipher, uint8_t *plain)
{
  __m128i m = _mm_loadu_si128 ((__m128i *) cipher);

  /* First round (key whitening) */
  m = _mm_xor_si128 (m, key_schedule[14 + 0]);

  /* Inner decryption rounds */
  m = _mm_aesdec_si128 (m, key_schedule[14 + 1]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 2]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 3]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 4]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 5]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 6]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 7]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 8]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 9]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 10]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 11]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 12]);
  m = _mm_aesdec_si128 (m, key_schedule[14 + 13]);

  /* Last decryption round */
  m = _mm_aesdeclast_si128 (m, key_schedule[0]);

  _mm_storeu_si128 ((__m128i *) plain, m);
}

#endif /* AES256_H */
