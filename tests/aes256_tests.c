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

#include "aes256.h"

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

/* Test AES-256 subkeys generation */
static void
aes256_keygen_tests (void)
{
  uint8_t key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t key0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t key1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t key2[] = { 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
                     0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63 };

  uint8_t key3[] = { 0xaa, 0xfb, 0xfb, 0xfb, 0xaa, 0xfb, 0xfb, 0xfb,
                     0xaa, 0xfb, 0xfb, 0xfb, 0xaa, 0xfb, 0xfb, 0xfb };

  uint8_t key4[] = { 0x6f, 0x6c, 0x6c, 0xcf, 0x0d, 0x0f, 0x0f, 0xac,
                     0x6f, 0x6c, 0x6c, 0xcf, 0x0d, 0x0f, 0x0f, 0xac };

  uint8_t key5[] = { 0x7d, 0x8d, 0x8d, 0x6a, 0xd7, 0x76, 0x76, 0x91,
                     0x7d, 0x8d, 0x8d, 0x6a, 0xd7, 0x76, 0x76, 0x91 };

  uint8_t key6[] = { 0x53, 0x54, 0xed, 0xc1, 0x5e, 0x5b, 0xe2, 0x6d,
                     0x31, 0x37, 0x8e, 0xa2, 0x3c, 0x38, 0x81, 0x0e };

  uint8_t key7[] = { 0x96, 0x8a, 0x81, 0xc1, 0x41, 0xfc, 0xf7, 0x50,
                     0x3c, 0x71, 0x7a, 0x3a, 0xeb, 0x07, 0x0c, 0xab };

  uint8_t key8[] = { 0x9e, 0xaa, 0x8f, 0x28, 0xc0, 0xf1, 0x6d, 0x45,
                     0xf1, 0xc6, 0xe3, 0xe7, 0xcd, 0xfe, 0x62, 0xe9 };

  uint8_t key9[] = { 0x2b, 0x31, 0x2b, 0xdf, 0x6a, 0xcd, 0xdc, 0x8f,
                     0x56, 0xbc, 0xa6, 0xb5, 0xbd, 0xbb, 0xaa, 0x1e };

  uint8_t key10[] = { 0x64, 0x06, 0xfd, 0x52, 0xa4, 0xf7, 0x90, 0x17,
                      0x55, 0x31, 0x73, 0xf0, 0x98, 0xcf, 0x11, 0x19 };

  uint8_t key11[] = { 0x6d, 0xbb, 0xa9, 0x0b, 0x07, 0x76, 0x75, 0x84,
                      0x51, 0xca, 0xd3, 0x31, 0xec, 0x71, 0x79, 0x2f };

  uint8_t key12[] = { 0xe7, 0xb0, 0xe8, 0x9c, 0x43, 0x47, 0x78, 0x8b,
                      0x16, 0x76, 0x0b, 0x7b, 0x8e, 0xb9, 0x1a, 0x62 };

  uint8_t key13[] = { 0x74, 0xed, 0x0b, 0xa1, 0x73, 0x9b, 0x7e, 0x25,
                      0x22, 0x51, 0xad, 0x14, 0xce, 0x20, 0xd4, 0x3b };

  uint8_t key14[] = { 0x10, 0xf8, 0x0a, 0x17, 0x53, 0xbf, 0x72, 0x9c,
                      0x45, 0xc9, 0x79, 0xe7, 0xcb, 0x70, 0x63, 0x85 };

  /* Setting key_schedule */
  __m128i key_schedule[28];
  aes256_load_key (key, key_schedule);

  EXPECT (memcmp (key0, (uint8_t *) &(key_schedule[0]), sizeof (key0)) == 0,
          "aes-256 subkey0");
  EXPECT (memcmp (key1, (uint8_t *) &(key_schedule[1]), sizeof (key1)) == 0,
          "aes-256 subkey1");
  EXPECT (memcmp (key2, (uint8_t *) &(key_schedule[2]), sizeof (key2)) == 0,
          "aes-256 subkey2");
  EXPECT (memcmp (key3, (uint8_t *) &(key_schedule[3]), sizeof (key3)) == 0,
          "aes-256 subkey3");
  EXPECT (memcmp (key4, (uint8_t *) &(key_schedule[4]), sizeof (key4)) == 0,
          "aes-256 subkey4");
  EXPECT (memcmp (key5, (uint8_t *) &(key_schedule[5]), sizeof (key5)) == 0,
          "aes-256 subkey5");
  EXPECT (memcmp (key6, (uint8_t *) &(key_schedule[6]), sizeof (key6)) == 0,
          "aes-256 subkey6");
  EXPECT (memcmp (key7, (uint8_t *) &(key_schedule[7]), sizeof (key7)) == 0,
          "aes-256 subkey7");
  EXPECT (memcmp (key8, (uint8_t *) &(key_schedule[8]), sizeof (key8)) == 0,
          "aes-256 subkey8");
  EXPECT (memcmp (key9, (uint8_t *) &(key_schedule[9]), sizeof (key9)) == 0,
          "aes-256 subkey9");
  EXPECT (memcmp (key10, (uint8_t *) &(key_schedule[10]), sizeof (key10)) == 0,
          "aes-256 subkey10");
  EXPECT (memcmp (key11, (uint8_t *) &(key_schedule[11]), sizeof (key11)) == 0,
          "aes-256 subkey11");
  EXPECT (memcmp (key12, (uint8_t *) &(key_schedule[12]), sizeof (key12)) == 0,
          "aes-256 subkey12");
  EXPECT (memcmp (key13, (uint8_t *) &(key_schedule[13]), sizeof (key13)) == 0,
          "aes-256 subkey13");
  EXPECT (memcmp (key14, (uint8_t *) &(key_schedule[14]), sizeof (key14)) == 0,
          "aes-256 subkey14");
}

/* Test AES-256 encryption */
static bool
aes256_encrypt_test (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                       0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

  /* Setting key_schedule */
  __m128i key_schedule[28];
  aes256_load_key_encrypt_only (key, key_schedule);

  /* Testing encryption */
  uint8_t computed_cipher[16];
  aes256_encrypt (key_schedule, plain, computed_cipher);

  return (memcmp (cipher, computed_cipher, sizeof (cipher)) == 0);
}

/* Test AES-256 decryption */
static int
aes256_decrypt_test (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                       0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

  /* Setting key_schedule */
  __m128i key_schedule[32];
  aes256_load_key (key, key_schedule);

  /* Testing decryption */
  uint8_t computed_plain[16];
  aes256_decrypt (key_schedule, cipher, computed_plain);

  return (memcmp (plain, computed_plain, sizeof (plain)) == 0);
}

/* Test AES-256 encryption/decryption performance */
static void
aes256_performance (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                       0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

  __m128i key_schedule[28];

  /* Number of encryptions per second */
  size_t count = 0;
  uint8_t computed[16];

  time_t slot = 10, deadline = time (NULL) + slot;
  while (time (NULL) < deadline)
    {
      /* Setting key_schedule */
      aes256_load_key_encrypt_only (key, key_schedule);

      /* Start encryption */
      aes256_encrypt (key_schedule, plain, computed);

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
      aes256_load_key (key, key_schedule);

      /* Start encryption */
      aes256_decrypt (key_schedule, cipher, computed);

      (*((uint64_t *) key))++;
      count++;
    }

  fprintf (stdout, "Decryptions: %zu/second\n", count / slot);
}

int
main (void)
{
  fprintf (stdout, "Testing AES-256\n===============\n");

  /* Unit tests */
  fprintf (stdout, "Unit tests\n-----------\n");
  aes256_keygen_tests ();
  fprintf (stdout, "\n");

  EXPECT (aes256_encrypt_test (), "check aes-256 encryption");
  EXPECT (aes256_decrypt_test (), "check aes-256 decryption");
  fprintf (stdout, "\n");

  /* Performance test */
  fprintf (stdout, "Performance tests\n------------------\n");
  aes256_performance ();
  fprintf (stdout, "\n");

  return EXIT_SUCCESS;
}
