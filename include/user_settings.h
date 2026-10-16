/*!
 * @file        include/user_settings.h
 * @description wolfCrypt and wolfSSH embedded configuration for W55RP20.
 * @author      Eltryus - Ricardo Marques
 * @copyright   2026 Eltryus - Ricardo Marques
 * @see         https://github.com/RicardoJCMarques/SSH.RP
 *
 * SPDX-FileCopyrightText: 2026 Eltryus - Ricardo Marques
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_NO_SOCK
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define WOLFSSL_SMALL_STACK

/* Hash-DRBG seeded by the Pico SDK entropy mixer (port/rpi_pico/pico.c) */
#define NO_DEV_RANDOM
#define WOLFSSL_RPIPICO
#define CUSTOM_RAND_GENERATE_SEED wc_pico_rng_gen_block

#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519
#define ED25519_SMALL
#define HAVE_ED25519_KEY_IMPORT
#define HAVE_ED25519_KEY_EXPORT
#define WOLFSSL_ED25519_STREAMING_VERIFY /* wolfSSH disables ssh-ed25519 without it */
#define WOLFSSL_SHA512
#define WOLFSSL_AES_COUNTER /* aes128-ctr; wolfSSH has no chacha20-poly1305 */

#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD5
#define NO_RC4
#define NO_DES3

/* WOLFSSL_ARDUINO (auto-set for Arduino on ARM) forces HAVE_ECC; keep wolfSSH off it */
#define ECC_TIMING_RESISTANT
#define WOLFSSH_NO_ECDH
#define WOLFSSH_NO_ECDSA

#define WOLFSSL_WOLFSSH
#define WOLFSSH_USER_IO
#define WOLFSSH_TERM
#define NO_TERMIOS
#define WOLFSSH_SMALL_STACK
#define NO_WOLFSSH_CLIENT
#define DEFAULT_WINDOW_SZ (4 * 1024)
#define DEFAULT_MAX_PACKET_SZ 1024

#endif /* USER_SETTINGS_H */