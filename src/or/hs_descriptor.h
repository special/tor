/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_descriptor.h
 * \brief Header file for hs_descriptor.c
 **/

#ifndef TOR_HS_DESCRIPTOR_H
#define TOR_HS_DESCRIPTOR_H

#include <stdint.h>

#include "address.h"
#include "container.h"
#include "crypto.h"
#include "crypto_ed25519.h"
#include "torcert.h"

/* Current descriptor format supported version. */
#define HS_DESC_SUPPORTED_FORMAT_VERSION 3

/* Length of the salt needed for the encrypted section of a descriptor. */
#define HS_DESC_ENCRYPTED_SALT_LEN 16
/* Length of the secret input needed for the KDF construction which derives
 * the encryption key for the encrypted data section of the descriptor. This
 * adds up to 68 bytes being the blinded key, hashed subcredential and
 * revision counter. */
#define HS_DESC_ENCRYPTED_SECRET_INPUT_LEN \
  ED25519_PUBKEY_LEN + DIGEST256_LEN + sizeof(uint32_t)
/* Length of the KDF output value which is the length of the secret key,
 * the secret IV and MAC key length which is the length of H() output. */
#define HS_DESC_ENCRYPTED_KDF_OUTPUT_LEN \
  CIPHER_KEY_LEN + CIPHER_IV_LEN + DIGEST256_LEN
/* We need to pad the plaintext version of the encrypted data section before
 * encryption and it has to be a multiple of this value. */
#define HS_DESC_ENCRYPTED_PADDING_PLAINTEXT_MULTIPLE 128
/* Once padded, this is the maximum length in bytes for the plaintext. */
#define HS_DESC_ENCRYPTED_PADDED_PLAINTEXT_MAX_LEN 8192

/* Link specifier object that contains information on how to extend to the
 * relay that is the address, port and handshake type. */
typedef struct hs_desc_link_specifier_t {
  /* Indicate the type of link specifier. See trunnel ed25519_cert
   * specification. */
  uint8_t type;

  /* It's either an address/port or a legacy identity fingerprint. */
  union {
    /* IP address and port of the relay use to extend. */
    tor_addr_port_t ap;
    /* Legacy identity. A 20-byte SHA1 identity fingerprint. */
    uint8_t legacy_id[DIGEST_LEN];
  } u;
} hs_desc_link_specifier_t;

/* Introduction point information located in a descriptor. */
typedef struct hs_desc_intro_point_t {
  /* Link specifier(s) which details how to extend to the relay. This list
   * contains hs_desc_link_specifier_t object. It MUST have at least one. */
  smartlist_t *link_specifiers;

  /* Authentication key used to establish the introduction point circuit and
   * cross-certifies the blinded public key for the replica. */
  tor_cert_t *auth_key_cert;

  /* Encryption key used to encrypt request to hidden service. */
  curve25519_keypair_t enc_key;

  /* Backward compat: RSA 1024 encryption key for legacy purposes. */
  crypto_pk_t *enc_key_legacy;
} hs_desc_intro_point_t;

/* The encrypted data section of a descriptor. Obviously the data in this is
 * in plaintext but encrypted once encoded. */
typedef struct hs_desc_encrypted_data_t {
  /* Bitfield of CREATE2 cell supported formats. The only currently supported
   * format is ntor. */
  unsigned int create2_ntor : 1;

  /* A list of authentication types that a client must at least support one
   * in order to contact the service. Contains NULL terminated strings. */
  smartlist_t *auth_types;

  /* A list of intro points. Contains hs_desc_intro_point_t objects. */
  smartlist_t *intro_points;
} hs_desc_encrypted_data_t;

/* Plaintext data that is unencrypted information of the descriptor. */
typedef struct hs_desc_plaintext_data_t {
  /* Version of the descriptor format. Spec specifies this field as a
   * positive integer. */
  uint32_t version;

  /* Certificate with the short-term ed22519 descriptor signing key for the
   * replica which is signed by the blinded public key for that replica. */
  tor_cert_t *signing_key_cert;

  /* Signing keypair which is used to sign the descriptor. Same public key
   * as in the signing key certificate. */
  ed25519_keypair_t signing_kp;

  /* Blinded keypair used for this descriptor derived from the master
   * identity key and generated for a specific replica number. */
  ed25519_keypair_t blinded_kp;

  /* Revision counter is incremented at each upload, regardless of whether
   * the descriptor has changed. This avoids leaking whether the descriptor
   * has changed. Spec specifies this as a 4 bytes positive integer. */
  uint32_t revision_counter;
} hs_desc_plaintext_data_t;

/* Service descriptor in its decoded form. */
typedef struct hs_descriptor_t {
  /* Contains the plaintext part of the descriptor. */
  hs_desc_plaintext_data_t plaintext_data;

  /* The following contains what's in the encrypted part of the descriptor.
   * It's only encrypted in the encoded version of the descriptor thus the
   * data contained in that object is in plaintext. */
  hs_desc_encrypted_data_t encrypted_data;

  /* Subcredentials of a service, used by the client and service to decrypt
   * the encrypted data. */
  uint8_t subcredential[DIGEST256_LEN];
} hs_descriptor_t;

/* Public API. */

void hs_descriptor_free(hs_descriptor_t *desc);
void hs_desc_plaintext_data_free(hs_desc_plaintext_data_t *desc);
void hs_desc_encrypted_data_free(hs_desc_encrypted_data_t *desc);

int hs_desc_encode_descriptor(const hs_descriptor_t *desc,
                              char **encoded_out);

#ifdef HS_DESCRIPTOR_PRIVATE

STATIC int encode_cert(const tor_cert_t *cert, char **cert_str_out);
STATIC char *encode_link_specifiers(const smartlist_t *specs);

#endif /* HS_DESCRIPTOR_PRIVATE */

#endif /* TOR_HS_DESCRIPTOR_H */
