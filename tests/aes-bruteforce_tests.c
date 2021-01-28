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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <byteswap.h>
#include <limits.h>
#include <omp.h>
#include <string.h>
#include <time.h>

#include "aes256.h" /* AES-256 encryption/decryption algoritms */

inline static void
print_128_block (char *block_name, uint8_t *block)
{
  fprintf (stdout, "%s:\n", block_name);
  for (int i = 0; i < 16; i++)
    {
      fprintf (stdout, "0x%02x ", block[i]);
      if (i % 8 == 7)
        fprintf (stdout, "\n");
    }
  fprintf (stdout, "\n");
}

inline static void
print_192_block (char *block_name, uint8_t *block)
{
  fprintf (stdout, "%s:\n", block_name);
  for (int i = 0; i < 24; i++)
    {
      fprintf (stdout, "0x%02x ", block[i]);
      if (i % 8 == 7)
        fprintf (stdout, "\n");
    }
  fprintf (stdout, "\n");
}

inline static void
print_256_block (char *block_name, uint8_t *block)
{
  fprintf (stdout, "%s:\n", block_name);
  for (int i = 0; i < 32; i++)
    {
      fprintf (stdout, "0x%02x ", block[i]);
      if (i % 8 == 7)
        fprintf (stdout, "\n");
    }
  fprintf (stdout, "\n");
}

/* Pure binary hexadecimal, no ASCII conversion */
inline static void
get_key_bytes (uint8_t *key, uint32_t key_counter)
{
  uint32_t reversed_key_counter = __bswap_32 (key_counter);

  /* Size of the key: sizeof (int) = 4 */
  *(uint32_t *) (&key[0]) = reversed_key_counter;
  *(uint32_t *) (&key[4]) = reversed_key_counter;
  *(uint32_t *) (&key[8]) = reversed_key_counter;
  *(uint32_t *) (&key[12]) = reversed_key_counter;
  *(uint32_t *) (&key[16]) = reversed_key_counter;
  *(uint32_t *) (&key[20]) = reversed_key_counter;
  *(uint32_t *) (&key[24]) = reversed_key_counter;
  *(uint32_t *) (&key[28]) = reversed_key_counter;
}

int
main ()
{
  /* Cipher key is 0x01234567 eight times */
  uint8_t ciphertext[] = {
    0x3a, 0x06, 0x0f, 0x9e, 0xb7, 0x89, 0xc4, 0xcc,
    0xb0, 0xa2, 0xdd, 0x8f, 0x39, 0x55, 0x5a, 0x7b,
  };

  fprintf (stdout,
           "Brute-force AES-256 on a 2^32 key space\n"
           "=======================================\n");
  clock_t clock_start = clock ();
  time_t time_start = time (NULL);

  /* Brute-force attack main loop */
#pragma omp parallel for
  for (uint32_t key_counter = 0; key_counter < UINT_MAX; key_counter++)
    {
      uint8_t key[32] = { 0 };
      uint8_t plaintext[16] = { 0 };
      __m128i key_schedule[28] = { 0 };

      /* Load key from key counter */
      get_key_bytes (key, key_counter);

      /* Decrypt the cipher with the current key */
      aes256_load_key (key, key_schedule);
      aes256_decrypt (key_schedule, ciphertext, plaintext);

      /* Check if deciphered block is zero */
      if (!(*((uint64_t *) &(plaintext[0]))) &&
          !(*((uint64_t *) &(plaintext[8]))))
        print_256_block ("Key candidate", key);
    }

  /* Final check on UINT_MAX to finish the search */
  uint8_t key[32] = { 0 };
  uint8_t plaintext[16] = { 0 };
  __m128i key_schedule[28] = { 0 };

  /* Load key from UINT_MAX */
  get_key_bytes (key, UINT_MAX);

  /* Decrypt the cipher with the current key as UINT_MAX */
  aes256_load_key (key, key_schedule);
  aes256_decrypt (key_schedule, ciphertext, plaintext);

  /* Check if deciphered block is zero */
  if (!(*((uint64_t *) &(plaintext[0]))) && !(*((uint64_t *) &(plaintext[8]))))
    print_256_block ("Key candidate", key);

  /* Getting the delay */
  clock_t clock_ticks = clock () - clock_start;
  time_t time_elapsed = time (NULL) - time_start;

  fprintf (stdout,
           "Performance of key space coverage:\n"
           " * real time (time really elapsed): %zus\n"
           " * full time (all core time added): %.0fs\n"
           " * speed up (full time / real time): %.02f\n",
           (size_t) time_elapsed,
           ((double) clock_ticks) / CLOCKS_PER_SEC,
           ((double) clock_ticks) / (CLOCKS_PER_SEC * (time_elapsed + 1)));
  fprintf (stdout, "\n");

  return EXIT_SUCCESS;
}
