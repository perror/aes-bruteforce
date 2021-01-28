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

#include "aes128.h"

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
aes128_keygen_tests (void)
{
  uint8_t key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t key0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t key1[] = { 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
                     0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63 };

  uint8_t key2[] = { 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
                     0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa };

  uint8_t key3[] = { 0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa,
                     0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f, 0xac, 0x99 };

  uint8_t key4[] = { 0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81,
                     0x75, 0x9e, 0x42, 0xb2, 0x7e, 0x91, 0xee, 0x2b };

  uint8_t key5[] = { 0x7f, 0x2e, 0x2b, 0x88, 0xf8, 0x44, 0x3e, 0x09,
                     0x8d, 0xda, 0x7c, 0xbb, 0xf3, 0x4b, 0x92, 0x90 };

  uint8_t key6[] = { 0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c,
                     0x99, 0xff, 0x09, 0x37, 0x6a, 0xb4, 0x9b, 0xa7 };

  uint8_t key7[] = { 0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b,
                     0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b, 0xf0, 0x9b };

  uint8_t key8[] = { 0x0e, 0xf9, 0x03, 0x33, 0x3b, 0xa9, 0x61, 0x38,
                     0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d, 0xfa, 0x9f };

  uint8_t key9[] = { 0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda,
                     0x1d, 0x7b, 0xb3, 0xde, 0x4c, 0x66, 0x49, 0x41 };

  uint8_t key10[] = { 0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11,
                      0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e };

  /* Setting key_schedule */
  __m128i key_schedule[24];
  aes128_load_key (key, key_schedule);

  EXPECT (memcmp (key0, (uint8_t *) &(key_schedule[0]), sizeof (key0)) == 0,
          "aes-128 subkey0");
  EXPECT (memcmp (key1, (uint8_t *) &(key_schedule[1]), sizeof (key1)) == 0,
          "aes-128 subkey1");
  EXPECT (memcmp (key2, (uint8_t *) &(key_schedule[2]), sizeof (key2)) == 0,
          "aes-128 subkey2");
  EXPECT (memcmp (key3, (uint8_t *) &(key_schedule[3]), sizeof (key3)) == 0,
          "aes-128 subkey3");
  EXPECT (memcmp (key4, (uint8_t *) &(key_schedule[4]), sizeof (key4)) == 0,
          "aes-128 subkey4");
  EXPECT (memcmp (key5, (uint8_t *) &(key_schedule[5]), sizeof (key5)) == 0,
          "aes-128 subkey5");
  EXPECT (memcmp (key6, (uint8_t *) &(key_schedule[6]), sizeof (key6)) == 0,
          "aes-128 subkey6");
  EXPECT (memcmp (key7, (uint8_t *) &(key_schedule[7]), sizeof (key7)) == 0,
          "aes-128 subkey7");
  EXPECT (memcmp (key8, (uint8_t *) &(key_schedule[8]), sizeof (key8)) == 0,
          "aes-128 subkey8");
  EXPECT (memcmp (key9, (uint8_t *) &(key_schedule[9]), sizeof (key9)) == 0,
          "aes-128 subkey9");
  EXPECT (memcmp (key10, (uint8_t *) &(key_schedule[10]), sizeof (key10)) == 0,
          "aes-128 subkey10");
}

/* First test on AES-128 encryption */
static bool
aes128_encrypt_test (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                       0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };

  /* Setting key_schedule */
  __m128i key_schedule[20];
  aes128_load_key (key, key_schedule);

  /* Testing encryption */
  uint8_t computed_cipher[16];
  aes128_encrypt (key_schedule, plain, computed_cipher);

  return (memcmp (cipher, computed_cipher, sizeof (cipher)) == 0);
}

/* First test on AES-128 decryption*/
static int
aes128_decrypt_test (void)
{
  uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

  uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  uint8_t cipher[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                       0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };

  /* Setting key_schedule */
  __m128i key_schedule[20];
  aes128_load_key (key, key_schedule);

  /* Testing decryption */
  uint8_t computed_plain[16];
  aes128_decrypt (key_schedule, cipher, computed_plain);

  return (memcmp (plain, computed_plain, sizeof (plain)) == 0);
}

/* Second test on AES-128 encryption */
static bool
aes128_encrypt_test2 (void)
{
  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

  uint8_t plain[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                      0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

  uint8_t cipher[] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                       0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

  /* Setting key_schedule */
  __m128i key_schedule[20];
  aes128_load_key (key, key_schedule);

  /* Testing encryption */
  uint8_t computed_cipher[16];
  aes128_encrypt (key_schedule, plain, computed_cipher);

  return (memcmp (cipher, computed_cipher, sizeof (cipher)) == 0);
}

/* Second test on AES-128 decryption */
static int
aes128_decrypt_test2 (void)
{
  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

  uint8_t plain[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                      0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

  uint8_t cipher[] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                       0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

  /* Setting key_schedule */
  __m128i key_schedule[20];
  aes128_load_key (key, key_schedule);

  /* Testing decryption */
  uint8_t computed_plain[16];
  aes128_decrypt (key_schedule, cipher, computed_plain);

  return (memcmp (plain, computed_plain, sizeof (plain)) == 0);
}

/* Test AES-128 encryption/decryption performance */
static void
aes128_performance (void)
{
  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

  uint8_t plain[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                      0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

  uint8_t cipher[] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                       0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

  __m128i key_schedule[20];

  /* Number of encryptions per second */
  size_t count = 0;
  uint8_t computed[16];

  time_t slot = 10, deadline = time (NULL) + slot;
  while (time (NULL) < deadline)
    {
      /* Setting key_schedule */
      aes128_load_key_encrypt_only (key, key_schedule);

      /* Start encryption */
      aes128_encrypt (key_schedule, plain, computed);

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
      aes128_load_key (key, key_schedule);

      /* Start encryption */
      aes128_decrypt (key_schedule, cipher, computed);

      (*((uint64_t *) key))++;
      count++;
    }

  fprintf (stdout, "Decryptions: %zu/second\n", count / slot);
}

int
main (void)
{
  fprintf (stdout, "Testing AES-128\n===============\n");

  /* Unit tests */
  fprintf (stdout, "Unit tests\n----------\n");
  aes128_keygen_tests ();
  fprintf (stdout, "\n");

  EXPECT (aes128_encrypt_test (), "aes-128 encryption (first)");
  EXPECT (aes128_decrypt_test (), "aes-128 decryption (first)");
  fprintf (stdout, "\n");

  EXPECT (aes128_encrypt_test2 (), "aes-128 encryption (second)");
  EXPECT (aes128_decrypt_test2 (), "aes-128 decryption (second)");
  fprintf (stdout, "\n");

  /* Performance test */
  fprintf (stdout, "Performance tests\n-----------------\n");
  aes128_performance ();
  fprintf (stdout, "\n");

  return EXIT_SUCCESS;
}
