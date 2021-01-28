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

#include "aes256.h" /* AES-256 encryption/decryption algoritms */

inline static void
print_128_block (char *block_name, uint8_t *block)
{
  fprintf (stdout, "%s:\n", block_name);
  for (size_t i = 0; i < 16; i++)
    {
      fprintf (stdout, "%02x ", block[i]);
      if (i % 8 == 7)
        fprintf (stdout, "\n");
    }
  fprintf (stdout, "\n");
}

inline static void
print_192_block (char *block_name, uint8_t *block)
{
  fprintf (stdout, "%s:\n", block_name);
  for (size_t i = 0; i < 24; i++)
    {
      fprintf (stdout, "%02x ", block[i]);
      if (i % 8 == 7)
        fprintf (stdout, "\n");
    }
  fprintf (stdout, "\n");
}

inline static void
print_256_block (char *block_name, uint8_t *block)
{
  fprintf (stdout, "%s:\n", block_name);
  for (size_t i = 0; i < 32; i++)
    {
      fprintf (stdout, "%02x ", block[i]);
      if (i % 8 == 7)
        fprintf (stdout, "\n");
    }
  fprintf (stdout, "\n");
}

static const uint8_t prng_sequence[255] =
  {
   0x8a, 0x5c, 0x6a, 0xdd, 0x1f, 0xea, 0x6e, 0xe2,
   0x10, 0xfc, 0x3c, 0x58, 0x55, 0xd2, 0x09, 0xb8,
   0xd4, 0xa7, 0x3e, 0xc9, 0xdc, 0xd9, 0x20, 0xe5,
   0x78, 0xb0, 0xaa, 0xb9, 0x12, 0x6d, 0xb5, 0x53,
   0x7c, 0x8f, 0xa5, 0xaf, 0x40, 0xd7, 0xf0, 0x7d,
   0x49, 0x6f, 0x24, 0xda, 0x77, 0xa6, 0xf8, 0x03,
   0x57, 0x43, 0x80, 0xb3, 0xfd, 0xfa, 0x92, 0xde,
   0x48, 0xa9, 0xee, 0x51, 0xed, 0x06, 0xae, 0x86,
   0x1d, 0x7b, 0xe7, 0xe9, 0x39, 0xa1, 0x90, 0x4f,
   0xc1, 0xa2, 0xc7, 0x0c, 0x41, 0x11, 0x3a, 0xf6,
   0xd3, 0xcf, 0x72, 0x5f, 0x3d, 0x9e, 0x9f, 0x59,
   0x93, 0x18, 0x82, 0x22, 0x74, 0xf1, 0xbb, 0x83,
   0xe4, 0xbe, 0x7a, 0x21, 0x23, 0xb2, 0x3b, 0x30,
   0x19, 0x44, 0xe8, 0xff, 0x6b, 0x1b, 0xd5, 0x61,
   0xf4, 0x42, 0x46, 0x79, 0x76, 0x60, 0x32, 0x88,
   0xcd, 0xe3, 0xd6, 0x36, 0xb7, 0xc2, 0xf5, 0x84,
   0x8c, 0xf2, 0xec, 0xc0, 0x64, 0x0d, 0x87, 0xdb,
   0xb1, 0x6c, 0x73, 0x99, 0xf7, 0x15, 0x05, 0xf9,
   0xc5, 0x9d, 0xc8, 0x1a, 0x13, 0xab, 0x7f, 0xd8,
   0xe6, 0x2f, 0xf3, 0x2a, 0x0a, 0xef, 0x97, 0x27,
   0x8d, 0x34, 0x26, 0x4b, 0xfe, 0xad, 0xd1, 0x5e,
   0xfb, 0x54, 0x14, 0xc3, 0x33, 0x4e, 0x07, 0x68,
   0x4c, 0x96, 0xe1, 0x47, 0xbf, 0xbc, 0xeb, 0xa8,
   0x28, 0x9b, 0x66, 0x9c, 0x0e, 0xd0, 0x98, 0x31,
   0xdf, 0x8e, 0x63, 0x65, 0xcb, 0x4d, 0x50, 0x2b,
   0xcc, 0x25, 0x1c, 0xbd, 0x2d, 0x62, 0xa3, 0x01,
   0xc6, 0xca, 0x8b, 0x9a, 0xa0, 0x56, 0x85, 0x4a,
   0x38, 0x67, 0x5a, 0xc4, 0x5b, 0x02, 0x91, 0x89,
   0x0b, 0x29, 0x5d, 0xac, 0x17, 0x94, 0x70, 0xce,
   0xb4, 0x95, 0xb6, 0x04, 0x3f, 0x0f, 0x16, 0x52,
   0xba, 0x45, 0x2e, 0x35, 0xe0, 0x81, 0x75, 0x37,
   0x71, 0x08, 0x7e, 0x1e, 0x2c, 0xa4, 0x69,
  };

inline static void
key_xor_prng (uint8_t *xored_key, uint8_t *key, uint8_t prng_state)
{
  for (size_t i = 0; i < 32; i++)
    xored_key[i] = key[i] ^ prng_sequence[(prng_state + 31 - i) % 255];
}

/* Converted to hexadecimal ASCII format */
inline static void
get_key_ascii_bytes (uint8_t *key, uint32_t key_counter)
{
  char ascii_key[8 + 1] = { 0 };
  uint32_t key_copy = key_counter;

  for (int i = 0; i < 8; i++)
    {
      char value = (char) (key_copy & 0xf);
      if (value < 0x0a)
        value += '0';
      else
        value += ('a' - 0x0a);
      ascii_key[8 - i - 1] = value;

      key_copy = key_copy >> 4;
    }

  /* Size of the key: sizeof (int in ASCII) = 8 */
  *(uint64_t *) (&key[0]) = *(uint64_t *) (&ascii_key[0]);
  *(uint64_t *) (&key[8]) = *(uint64_t *) (&ascii_key[0]);
  *(uint64_t *) (&key[16]) = *(uint64_t *) (&ascii_key[0]);
  *(uint64_t *) (&key[24]) = *(uint64_t *) (&ascii_key[0]);
}

/* Pure binary hexadecimal, no ASCII conversion */
inline static void
get_key_bytes (uint8_t *key, uint32_t key_counter)
{
  /* Reversing the key (little-endian) */
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

/* Rebuilding factory key from srand() */
inline static void
get_factory_key (uint8_t *key, uint32_t key_counter)
{
  srand (key_counter);

  *(uint32_t *) (&key[0]) = rand ();
  *(uint32_t *) (&key[4]) = rand ();
  *(uint32_t *) (&key[8]) = rand ();
  *(uint32_t *) (&key[12]) = rand ();
  *(uint32_t *) (&key[16]) = rand ();
  *(uint32_t *) (&key[20]) = rand ();
  *(uint32_t *) (&key[24]) = rand ();
  *(uint32_t *) (&key[28]) = rand ();
}

/* Rebuilding factory reversed key from srand() */
inline static void
get_factory_reversed_key (uint8_t *key, uint32_t key_counter)
{
  srand (key_counter);

  *(uint32_t *) (&key[0]) = __bswap_32 (rand ());
  *(uint32_t *) (&key[4]) = __bswap_32 (rand ());
  *(uint32_t *) (&key[8]) = __bswap_32 (rand ());
  *(uint32_t *) (&key[12]) = __bswap_32 (rand ());
  *(uint32_t *) (&key[16]) = __bswap_32 (rand ());
  *(uint32_t *) (&key[20]) = __bswap_32 (rand ());
  *(uint32_t *) (&key[24]) = __bswap_32 (rand ());
  *(uint32_t *) (&key[28]) = __bswap_32 (rand ());
}

int
main ()
{
  /* Block supposed to be an encrypted '0'-block with an unknown AES-256 key */
  uint8_t ciphertext[] = {
    0xb9, 0x09, 0xb5, 0xe9, 0x36, 0x69, 0x7a, 0x0a,
    0x80, 0xfd, 0xc8, 0x3b, 0xf0, 0xb5, 0x6b, 0x57,
  };

  /* Some test cases with get_key_bytes() */
  /* ************************************ */

  /* Key counter = 00000000
   * Key = b8 09 d2 55 58 3c fc 10
   *       e2 6e ea 1f dd 6a 5c 8a
   *       69 a4 2c 1e 7e 08 71 37
   *       75 81 e0 35 2e 45 ba 52 */
  /*  uint8_t ciphertext[] = {
     0x79, 0x9c, 0x48, 0x15, 0x26, 0xa2, 0x55, 0xf2,
     0xc7, 0x7b, 0xff, 0xa0, 0x57, 0xd1, 0x42, 0x90,
     }; */

  /* Key counter = 01234567
   * Key = b9 2a 97 32 59 1f b9 77
   *       e3 4d af 78 dc 49 19 ed
   *       68 87 69 79 7f 2b 34 50
   *       74 a2 a5 52 2f 66 ff 35 */
  /*  uint8_t ciphertext[] = {
     0x4e, 0xc2, 0x17, 0xc4, 0x53, 0x78, 0xa3, 0xc3,
     0xe2, 0x16, 0x14, 0x3c, 0x97, 0xd0, 0xb9, 0xf1,
     }; */

  /* Some test cases with get_key_ascii_bytes() */
  /* ****************************************** */

  /* Key counter = 00000000
   * Key = 88 39 e2 65 68 3c 0c 20
   *       d2 5e da 2f ed 5a 6c ba
   *       59 94 1c 2e 4e 38 41 07
   *       45 b1 d0 05 1e 75 8a 62 */
  /*    uint8_t ciphertext[] = {
     0xfb, 0x6d, 0x28, 0x3d, 0xff, 0x82, 0xee, 0x3d,
     0x19, 0xb3, 0x1d, 0xd0, 0x42, 0x0e, 0x65, 0x87,
     }; */

  /* Key counter = 14efa8ff
   * Key = 89 3d b7 33 39 04 9a 76
   *       d3 5a 8f 79 bc 52 3a ec
   *	   58 90 49 78 1f 30 17 51
   *	   44 b5 85 53 4f 7d dc 34 */
  /*  uint8_t ciphertext[] = {
     0xa0, 0xe1, 0xeb, 0x5f, 0x39, 0x2d, 0x56, 0xe5,
     0x47, 0xfe, 0x2f, 0x80, 0x98, 0x2c, 0x95, 0x56,
     }; */

  /* Brute-force attack main loop */
#pragma omp parallel for
  for (uint32_t key_counter = 0; key_counter < UINT_MAX; key_counter++)
    {
      uint8_t plaintext[16] = { 0 };
      uint8_t key[32] = { 0 }, xored_key[32] = { 0 };
      __m128i key_schedule[28] = { 0 };

      /* Compute key from key counter */
      get_key_ascii_bytes (key, key_counter);

      for (int state = 0; state < 255; state++)
        {
          /* Xor the key derived from key counter with prng state */
          key_xor_prng (xored_key, key, state);

          /* Decrypt the cipher with the current key */
          aes256_load_key (xored_key, key_schedule);
          aes256_decrypt (key_schedule, ciphertext, plaintext);

          /* Check if deciphered block is zero */
          if (!(*((uint64_t *) &(plaintext[0]))) &&
              !(*((uint64_t *) &(plaintext[8]))))
            print_256_block ("Key candidate", xored_key);
        }
    }

  /* Final check on UINT_MAX to finish the search */
  uint8_t plaintext[16] = { 0 };
  uint8_t key[32] = { 0 }, xored_key[32] = { 0 };
  __m128i key_schedule[28] = { 0 };

  /* Compute key from UINT_MAX */
  get_key_ascii_bytes (key, UINT_MAX);

  for (int state = 0; state < 255; state++)
    {
      /* Xor the key derived from UINT_MAX with prng state */
      key_xor_prng (xored_key, key, state);

      /* Decrypt the cipher with the current key */
      aes256_load_key (xored_key, key_schedule);
      aes256_decrypt (key_schedule, ciphertext, plaintext);

      /* Check if deciphered block is zero */
      if (!(*((uint64_t *) &(plaintext[0]))) &&
          !(*((uint64_t *) &(plaintext[8]))))
        print_256_block ("Key candidate", xored_key);
    }

  return EXIT_SUCCESS;
}
