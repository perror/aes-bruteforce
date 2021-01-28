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

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>

#include "aes192.h"

#define SET_GREEN "\033[1;32m"
#define SET_RED "\033[1;31m"
#define RESET "\033[0m"

void
EXPECT (bool test, char *fmt, ...)
{
  fprintf (stdout, "Checking '");

  va_list vargs;
  va_start (vargs, fmt);
  vprintf (fmt, vargs);
  va_end (vargs);

  if (test)
    fprintf (stdout, "': " SET_GREEN "passed!" RESET "\n");
  else
    fprintf (stdout, "': " SET_RED "failed!" RESET "\n");
}

void
ASSERT (bool test, char *fmt, ...)
{
  fprintf (stdout, "Checking '");

  va_list vargs;
  va_start (vargs, fmt);
  vprintf (fmt, vargs);
  va_end (vargs);

  if (test)
    fprintf (stdout, "': " SET_GREEN "passed!" RESET "\n");
  else
    {
      fprintf (stdout, "': " SET_RED "critical fail!" RESET " aborting...\n");
      exit (EXIT_FAILURE);
    }
}

/* Test AES-128 subkeys generation */
static void
aes192_keygen_tests (void)
{
  uint8_t key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t key0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t key1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63 };

  uint8_t key2[] = { 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
                     0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63 };

  uint8_t key3[] = { 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
                     0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa };

  uint8_t key4[] = { 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
                     0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa };

  uint8_t key5[] = { 0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f, 0xac, 0x99,
                     0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa };

  uint8_t key6[] = { 0xc8, 0x1d, 0x19, 0xa9, 0xa1, 0x71, 0xd6, 0x53,
                     0x53, 0x85, 0x81, 0x60, 0x58, 0x8a, 0x2d, 0xf9 };

  uint8_t key7[] = { 0xc8, 0x1d, 0x19, 0xa9, 0xa1, 0x71, 0xd6, 0x53,
                     0x7b, 0xeb, 0xf4, 0x9b, 0xda, 0x9a, 0x22, 0xc8 };

  uint8_t key8[] = { 0x89, 0x1f, 0xa3, 0xa8, 0xd1, 0x95, 0x8e, 0x51,
                     0x19, 0x88, 0x97, 0xf8, 0xb8, 0xf9, 0x41, 0xab };

  uint8_t key9[] = { 0xc2, 0x68, 0x96, 0xf7, 0x18, 0xf2, 0xb4, 0x3f,
                     0x91, 0xed, 0x17, 0x97, 0x40, 0x78, 0x99, 0xc6 };

  uint8_t key10[] = { 0x59, 0xf0, 0x0e, 0x3e, 0xe1, 0x09, 0x4f, 0x95,
                      0x83, 0xec, 0xbc, 0x0f, 0x9b, 0x1e, 0x08, 0x30 };

  uint8_t key11[] = { 0x0a, 0xf3, 0x1f, 0xa7, 0x4a, 0x8b, 0x86, 0x61,
                      0x13, 0x7b, 0x88, 0x5f, 0xf2, 0x72, 0xc7, 0xca };

  uint8_t key12[] = { 0x43, 0x2a, 0xc8, 0x86, 0xd8, 0x34, 0xc0, 0xb6,
                      0xd2, 0xc7, 0xdf, 0x11, 0x98, 0x4c, 0x59, 0x70 };

  /* Setting key_schedule */
  __m128i key_schedule[24];
  aes192_load_key (key, key_schedule);

  EXPECT (memcmp (key0, (uint8_t *) &(key_schedule[0]), sizeof (key0)) == 0,
          "aes-192 subkey0");
  EXPECT (memcmp (key1, (uint8_t *) &(key_schedule[1]), sizeof (key1)) == 0,
          "aes-192 subkey1");
  EXPECT (memcmp (key2, (uint8_t *) &(key_schedule[2]), sizeof (key2)) == 0,
          "aes-192 subkey2");
  EXPECT (memcmp (key3, (uint8_t *) &(key_schedule[3]), sizeof (key3)) == 0,
          "aes-192 subkey3");
  EXPECT (memcmp (key4, (uint8_t *) &(key_schedule[4]), sizeof (key4)) == 0,
          "aes-192 subkey4");
  EXPECT (memcmp (key5, (uint8_t *) &(key_schedule[5]), sizeof (key5)) == 0,
          "aes-192 subkey5");
  EXPECT (memcmp (key6, (uint8_t *) &(key_schedule[6]), sizeof (key6)) == 0,
          "aes-192 subkey6");
  EXPECT (memcmp (key7, (uint8_t *) &(key_schedule[7]), sizeof (key7)) == 0,
          "aes-192 subkey7");
  EXPECT (memcmp (key8, (uint8_t *) &(key_schedule[8]), sizeof (key8)) == 0,
          "aes-192 subkey8");
  EXPECT (memcmp (key9, (uint8_t *) &(key_schedule[9]), sizeof (key9)) == 0,
          "aes-192 subkey9");
  EXPECT (memcmp (key10, (uint8_t *) &(key_schedule[10]), sizeof (key10)) == 0,
          "aes-192 subkey10");
  EXPECT (memcmp (key11, (uint8_t *) &(key_schedule[11]), sizeof (key11)) == 0,
          "aes-192 subkey11");
  EXPECT (memcmp (key12, (uint8_t *) &(key_schedule[12]), sizeof (key12)) == 0,
          "aes-192 subkey12");
}

/* Test AES-192 encryption */
static bool
aes192_encrypt_test (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                       0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

  /* Setting key_schedule */
  __m128i key_schedule[24];
  aes192_load_key (key, key_schedule);

  /* Testing encryption */
  uint8_t computed_cipher[16];
  aes192_encrypt (key_schedule, plain, computed_cipher);

  return (memcmp (cipher, computed_cipher, sizeof (cipher)) == 0);
}

/* Test AES-192 decryption */
static int
aes192_decrypt_test (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                       0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

  /* Setting key_schedule */
  __m128i key_schedule[24];
  aes192_load_key (key, key_schedule);

  /* Testing decryption */
  uint8_t computed_plain[16];
  aes192_decrypt (key_schedule, cipher, computed_plain);

  return (memcmp (plain, computed_plain, sizeof (plain)) == 0);
}

/* Test AES-192 encryption/decryption performance */
static void
aes192_performance (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                       0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

  __m128i key_schedule[24];

  /* Number of encryptions per second */
  size_t count = 0;
  uint8_t computed[16];

  time_t slot = 10, deadline = time (NULL) + slot;
  while (time (NULL) < deadline)
    {
      /* Setting key_schedule */
      aes192_load_key_encrypt_only (key, key_schedule);

      /* Start encryption */
      aes192_encrypt (key_schedule, plain, computed);

      (*((uint64_t *) key))++;
      count++;
    }
  fprintf (stdout, "Encryptions: %zu/second\n", count / slot);

  /* Number of decryptions per second */
  count = 0;
  deadline = time (NULL) + slot;
  while (time (NULL) < deadline)
    {
      /* Setting key_schedule */
      aes192_load_key (key, key_schedule);

      /* Start encryption */
      aes192_decrypt (key_schedule, cipher, computed);

      (*((uint64_t *) key))++;
      count++;
    }

  fprintf (stdout, "Decryptions: %zu/second\n", count / slot);
}

int
main (void)
{
  fprintf (stdout, "Testing AES-192\n===============\n");

  /* Unit tests */
  fprintf (stdout, "Unit tests\n-----------\n");
  aes192_keygen_tests ();
  fprintf (stdout, "\n");

  EXPECT (aes192_encrypt_test (), "aes-192 encryption");
  EXPECT (aes192_decrypt_test (), "aes-192 decryption");
  fprintf (stdout, "\n");

  /* Performance test */
  fprintf (stdout, "Performance tests\n------------------\n");
  aes192_performance ();
  fprintf (stdout, "\n");

  return EXIT_SUCCESS;
}
