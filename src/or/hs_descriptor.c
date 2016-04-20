/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_descriptor.c
 * \brief Handle hidden service descriptor encoding/decoding.
 **/

/* For unit tests.*/
#define HS_DESCRIPTOR_PRIVATE

#include "hs_descriptor.h"

#include "or.h"
#include "ed25519_cert.h" /* Trunnel interface. */

/* Constant string value used for the descriptor format. */
static const char *str_hs_desc = "hs-descriptor";
static const char *str_desc_cert = "descriptor-signing-key-cert";
static const char *str_rev_counter = "revision-counter";
static const char *str_encrypted = "encrypted";
static const char *str_signature = "signature";
/* Constant string value for the encrypted part of the descriptor. */
static const char *str_create2_formats = "create2-formats";
static const char *str_auth_required = "authentication-required";
static const char *str_intro_point = "introduction-point";
static const char *str_ip_auth_key = "auth-key";
static const char *str_ip_enc_key = "enc-key";
/* Constant string value for the construction to encrypt the encrypted data
 * section. */
static const char *str_enc_hsdir_data = "hsdir-encrypted-data";

/* Encode an ed25519 certificate type and put the newly allocated string in
 * cert_str_out. Return 0 on success else a negative value. */
STATIC int
encode_cert(const tor_cert_t *cert, char **cert_str_out)
{
  int ret;
  char *ed_cert_b64 = NULL;
  size_t ed_cert_b64_len;

  tor_assert(cert);
  tor_assert(cert_str_out);

  /* Get the encoded size and add the NULL byte. */
  ed_cert_b64_len = base64_encode_size(cert->encoded_len,
                                       BASE64_ENCODE_MULTILINE) + 1;
  ed_cert_b64 = tor_malloc_zero(ed_cert_b64_len);

  /* Base64 encode the encoded certificate. */
  ret = base64_encode(ed_cert_b64, ed_cert_b64_len,
                      (const char *) cert->encoded, cert->encoded_len,
                      BASE64_ENCODE_MULTILINE);
  if (ret < 0) {
    log_err(LD_BUG, "Couldn't base64-encode descriptor signing key cert!");
    goto err;
  }

  /* Put everything together in a NULL terminated string. */
  tor_asprintf(cert_str_out,
               "identity-ed25519\n"
               "-----BEGIN ED25519 CERT-----\n"
               "%s"
               "-----END ED25519 CERT-----",
               ed_cert_b64);
  /* Success! */
  ret = 0;

err:
  tor_free(ed_cert_b64);
  return ret;
}

/* Return an allocated string containing a space separated list of handshake
 * type. NULL is returned if no handshake type were enabled. */
STATIC char *
encode_create2_list(unsigned int create2_bitmask)
{
  int nbit;
  char *formats = NULL;

  for (nbit = 1; nbit <= MAX_ONION_HANDSHAKE_TYPE; nbit++) {
    char *buf;

    /* Skip if we don't have the handshake enabled. */
    if (!(create2_bitmask & nbit)) {
      continue;
    }

    if (formats == NULL) {
      /* First value to find, format it and try next. */
      tor_asprintf(&formats, "%d", nbit);
      continue;
    }
    tor_asprintf(&buf, "%s %d", formats, nbit);
    tor_free(formats);
    formats = buf;
  }

  return formats;
}

/* Encode the given link specifier object into a newly allocated string.
 * This can't fail so caller can always assume a valid string being
 * returned. */
STATIC char *
encode_link_specifiers(const smartlist_t *specs)
{
  /* Base64 encoded line containing all link specifiers. */
  char *ls_b64 = NULL;
  /* Buffer holding the binary encoded link specifier(s). */
  struct {
    size_t len;
    uint8_t *buf;
  } encoded_ls = { 0, NULL };

  tor_assert(specs);
  /* No link specifiers is a code flow error, can't happen. */
  tor_assert(smartlist_len(specs) > 0);
  tor_assert(smartlist_len(specs) <= UINT8_MAX);

  /* First, we'll put our number of link specifier at the start of our
   * encoded buffer. NSPEC is specified in tor-spec.txt as 1 byte. */
  encoded_ls.len = sizeof(uint8_t);
  encoded_ls.buf = tor_malloc_zero(encoded_ls.len);
  set_uint8(encoded_ls.buf, smartlist_len(specs));

  SMARTLIST_FOREACH_BEGIN(specs, const hs_desc_link_specifier_t *,
                          spec) {
    link_specifier_t *ls = link_specifier_new();
    link_specifier_set_ls_type(ls, spec->type);

    switch (spec->type) {
    case LS_IPV4:
      link_specifier_set_un_ipv4_addr(ls,
                                      tor_addr_to_ipv4h(&spec->u.ap.addr));
      link_specifier_set_un_ipv4_port(ls, spec->u.ap.port);
      /* Four bytes IPv4 and two bytes port. */
      link_specifier_set_ls_len(ls, sizeof(spec->u.ap.addr.addr.in_addr) +
                                    sizeof(spec->u.ap.port));
      break;
    case LS_IPV6:
    {
      size_t addr_len = link_specifier_getlen_un_ipv6_addr(ls);
      const uint8_t *in6_addr = tor_addr_to_in6_addr8(&spec->u.ap.addr);
      for (size_t idx = 0; idx < addr_len; idx++) {
        link_specifier_set_un_ipv6_addr(ls, idx, in6_addr[idx]);
      }
      link_specifier_set_un_ipv6_port(ls, spec->u.ap.port);
      /* Sixteen bytes IPv6 and two bytes port. */
      link_specifier_set_ls_len(ls, addr_len + sizeof(spec->u.ap.port));
      break;
    }
    case LS_LEGACY_ID:
    {
      size_t legady_id_len = link_specifier_getlen_un_legacy_id(ls);
      for (size_t idx = 0; idx < legady_id_len; idx++) {
        link_specifier_set_un_legacy_id(ls, idx, spec->u.legacy_id[idx]);
      }
      link_specifier_set_ls_len(ls, legady_id_len);
      break;
    }
    default:
      tor_assert(0);
    }

    /* Binary encode our object and append to our list of encoded link
     * specifier so we can then base64 encode the whole chain. */
    {
      ssize_t bin_encoded_len, ret_len;
      bin_encoded_len = link_specifier_encoded_len(ls);
      tor_assert(bin_encoded_len > 0);
      encoded_ls.len += bin_encoded_len;
      /* Realloc our encoded buffer to fit the new size. */
      encoded_ls.buf = tor_realloc(encoded_ls.buf, encoded_ls.len);
      /* Encode the link specifier and put is in our newly allocated memory
       * that is at the end of the encoded buffer. */
      ret_len = link_specifier_encode(encoded_ls.buf +
                                      (encoded_ls.len - bin_encoded_len),
                                      bin_encoded_len, ls);
      tor_assert(ret_len == bin_encoded_len);
    }
    /* No need, free it and go to the next. */
    link_specifier_free(ls);
  } SMARTLIST_FOREACH_END(spec);

  /* Base64 encode our binary format. Add extra NULL byte for the base64
   * encoded value. */
  {
    ssize_t ret_len, ls_b64_len;
    ls_b64_len = base64_encode_size(encoded_ls.len, 0) + 1;
    ls_b64 = tor_malloc_zero(ls_b64_len);
    ret_len = base64_encode(ls_b64, ls_b64_len, (const char *) encoded_ls.buf,
                            encoded_ls.len, 0);
    tor_assert(ret_len == (ls_b64_len - 1));
  }

  tor_free(encoded_ls.buf);
  return ls_b64;
}

/* Encode an introductin point object and return a newly allocated string
 * with it. On failure, return NULL. */
static char *
encode_intro_point(const hs_desc_intro_point_t *ip)
{
  char *line_str, *encoded_ip = NULL;
  smartlist_t *lines = smartlist_new();

  tor_assert(ip);

  /* Encode link specifier. */
  {
    char *ls_str = encode_link_specifiers(ip->link_specifiers);
    tor_asprintf(&line_str, "%s %s", str_intro_point, ls_str);
    smartlist_add(lines, line_str);
    tor_free(ls_str);
  }

  /* Authentication key encoding. */
  {
    char *encoded_cert;
    if (encode_cert(ip->auth_key_cert, &encoded_cert) < 0) {
      goto err;
    }
    tor_asprintf(&line_str, "%s ed22519 %s", str_ip_auth_key, encoded_cert);
    smartlist_add(lines, line_str);
    tor_free(encoded_cert);
  }

  /* Encryption key encoding. */
  {
    char key_fp_b64[CURVE25519_BASE64_PADDED_LEN + 1];
    if (curve25519_public_to_base64(key_fp_b64, &ip->enc_key.pubkey) < 0) {
      goto err;
    }
    tor_asprintf(&line_str, "%s ntor %s", str_ip_enc_key, key_fp_b64);
    smartlist_add(lines, line_str);
  }

  /* Legacy encryption key encoding. */
  {
    char *key_str;
    size_t key_str_len;
    if (crypto_pk_write_public_key_to_string(ip->enc_key_legacy, &key_str,
                                             &key_str_len) < 0) {
      goto err;
    }
    tor_asprintf(&line_str, "%s legacy %s", str_ip_enc_key, key_str);
    smartlist_add(lines, line_str);
    tor_free(key_str);
  }

  /* Join them all in one blob of text. */
  encoded_ip = smartlist_join_strings(lines, "\n", 1, NULL);

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  return encoded_ip;
}

/* Using a given decriptor object, build the secret input needed for the
 * KDF and put it in the dst pointer which is an already allocated buffer
 * of size dstlen. */
static void
build_secret_input(const hs_descriptor_t *desc, uint8_t *dst, size_t dstlen)
{
  size_t offset = 0;

  tor_assert(desc);
  tor_assert(dst);

  /* Copy blinded public key. */
  memcpy(dst, desc->plaintext_data.blinded_kp.pubkey.pubkey,
         sizeof(desc->plaintext_data.blinded_kp.pubkey.pubkey));
  offset += sizeof(desc->plaintext_data.blinded_kp.pubkey.pubkey);
  tor_assert(offset < dstlen);
  /* Copy subcredential. */
  memcpy(dst + offset, desc->subcredential,
         sizeof(desc->subcredential));
  offset += sizeof(desc->subcredential);
  tor_assert(offset < dstlen);
  /* Copy revision counter value. */
  set_uint32(dst + offset, desc->plaintext_data.revision_counter);
  offset += sizeof(desc->plaintext_data.revision_counter);
  tor_assert(offset <= dstlen);
}

/* Do the KDF construction and put the resulting data in key_out which is of
 * key_out_len length. It uses SHAKE-256 as specified in the spec. */
static void
build_kdf_key(const hs_descriptor_t *desc,
              uint8_t *salt, size_t salt_len,
              uint8_t *key_out, size_t key_out_len)
{
  uint8_t secret_input[HS_DESC_ENCRYPTED_SECRET_INPUT_LEN];
  crypto_xof_t *xof;

  tor_assert(desc);
  tor_assert(salt);
  tor_assert(key_out);

  /* Build the secret input for the KDF computation. */
  build_secret_input(desc, secret_input, sizeof(secret_input));

  xof = crypto_xof_new();
  /* Feed our KDF. [SHAKE it like a polaroid picture --Yawning]. */
  crypto_xof_add_bytes(xof, secret_input, sizeof(secret_input));
  crypto_xof_add_bytes(xof, salt, salt_len);
  crypto_xof_add_bytes(xof, (const uint8_t *) str_enc_hsdir_data,
                       strlen(str_enc_hsdir_data));
  /* Eat from our KDF. */
  crypto_xof_squeeze_bytes(xof, key_out, key_out_len);
  crypto_xof_free(xof);
  memwipe(secret_input,  0, sizeof(secret_input));
}

/* Given a buffer plaintext, pad it up to the encrypted section padding
 * requirement. Set the newly allocated string in padded_out and return the
 * length of the padded buffer. */
static size_t
build_plaintext_padding(const char *plaintext, size_t plaintext_len,
                        uint8_t **padded_out)
{
  size_t padded_len;
  uint8_t *padded;

  tor_assert(plaintext);
  tor_assert(padded_out);

  /* Compute the final length we need with padding. */
  padded_len = plaintext_len +
    (HS_DESC_ENCRYPTED_PADDING_PLAINTEXT_MULTIPLE -
     (plaintext_len % HS_DESC_ENCRYPTED_PADDING_PLAINTEXT_MULTIPLE));
  padded = tor_malloc_zero(padded_len);

  memcpy(padded, plaintext, plaintext_len);
  /* Add the NUL bytes to the rest of the new padded buffer. */
  memset(padded + plaintext_len, 0, padded_len - plaintext_len);
  *padded_out = padded;
  return padded_len;
}

/* Using a key, IV and plaintext data of length plaintext_len, create the
 * encrypted section by encrypting it and setting encrypted_out with the
 * data. Return size of the encrypted data buffer. */
static size_t
build_encrypted(const uint8_t *key, const uint8_t *iv, const char *plaintext,
                size_t plaintext_len, uint8_t **encrypted_out)
{
  size_t encrypted_len, padded_len;
  uint8_t *padded_plaintext, *encrypted;
  crypto_cipher_t *cipher;

  tor_assert(key);
  tor_assert(iv);
  tor_assert(plaintext);
  tor_assert(encrypted_out);

  /* This creates a cipher for AES128. It can't fail. */
  cipher = crypto_cipher_new_with_iv((const char *) key, (const char *) iv);
  /* This can't fail. */
  padded_len = build_plaintext_padding(plaintext, plaintext_len,
                                       &padded_plaintext);
  /* Extra precautions that we have a valie padding length. */
  tor_assert(padded_len <= HS_DESC_ENCRYPTED_PADDED_PLAINTEXT_MAX_LEN);
  tor_assert(!(padded_len % HS_DESC_ENCRYPTED_PADDING_PLAINTEXT_MULTIPLE));
  /* We use a stream cipher so the encrypted length will be the same as the
   * plaintext padded length. */
  encrypted_len = padded_len;
  encrypted = tor_malloc_zero(encrypted_len);
  /* This can't fail. */
  crypto_cipher_encrypt(cipher, (char *) encrypted,
                        (const char *) padded_plaintext, encrypted_len);
  *encrypted_out = encrypted;
  /* Cleanup. */
  crypto_cipher_free(cipher);
  tor_free(padded_plaintext);
  return encrypted_len;
}

/* Encrypt the given plaintext buffer and using the descriptor to get the
 * keys. Set encrypted_out with the encrypted data and return the length of
 * it. */
static size_t
encrypt_data(const hs_descriptor_t *desc, const char *plaintext,
             char **encrypted_out)
{
  char *final_blob;
  size_t encrypted_len, final_blob_len, offset = 0;
  uint8_t *encrypted;
  uint8_t salt[HS_DESC_ENCRYPTED_SALT_LEN];
  uint8_t secret_key[CIPHER_KEY_LEN], secret_iv[CIPHER_IV_LEN];
  uint8_t mac_key[DIGEST256_LEN], mac[DIGEST256_LEN];

  tor_assert(desc);
  tor_assert(plaintext);
  tor_assert(encrypted_out);

  /* Get our salt. The returned bytes are already hashed. */
  crypto_strongest_rand(salt, sizeof(salt));

  /* KDF construction resulting in a key from which we'll extract what we
   * need for the encryption. */
  {
    uint8_t key[HS_DESC_ENCRYPTED_KDF_OUTPUT_LEN];

    build_kdf_key(desc, salt, sizeof(salt), key, sizeof(key));
    /* Copy the bytes we need for both the secret key and IV. */
    memcpy(secret_key, key, sizeof(secret_key));
    offset += sizeof(secret_key);
    memcpy(secret_iv, key + offset, sizeof(secret_iv));
    offset += sizeof(secret_iv);
    memcpy(mac_key, key + offset, sizeof(mac_key));
    /* Extra precaution to make sure we are not out of bound. */
    tor_assert((offset + sizeof(mac_key)) == sizeof(key));
    memwipe(key, 0, sizeof(key));
  }

  /* Build the encrypted part that is do the actual encryption. */
  encrypted_len = build_encrypted(secret_key, secret_iv, plaintext,
                                  strlen(plaintext), &encrypted);
  memwipe(secret_key, 0, sizeof(secret_key));
  memwipe(secret_iv, 0, sizeof(secret_iv));
  /* This construction is specified in section 2.5 of proposal 224. */
  final_blob_len = sizeof(salt) + encrypted_len + DIGEST256_LEN;
  final_blob = tor_malloc_zero(final_blob_len);

  /* Build the MAC. */
  {
    crypto_digest_t *digest;

    digest = crypto_digest256_new(DIGEST_SHA3_256);
    /* As specified in section 2.5 of proposal 224, first add the mac key
     * then add the salt first and then the encrypted section. */
    crypto_digest_add_bytes(digest, (const char *) mac_key,
                            sizeof(mac_key));
    crypto_digest_add_bytes(digest, (const char *) salt, sizeof(salt));
    crypto_digest_add_bytes(digest, (const char *) encrypted,
                            encrypted_len);
    crypto_digest_get_digest(digest, (char *) mac, sizeof(mac));
    crypto_digest_free(digest);
    memwipe(mac_key, 0, sizeof(mac_key));
  }

  /* The salt is the first value. */
  memcpy(final_blob, salt, sizeof(salt));
  offset = sizeof(salt);
  /* Second value is the encrypted data. */
  memcpy(final_blob + offset, encrypted, encrypted_len);
  offset += encrypted_len;
  /* Third value is the MAC. */
  memcpy(final_blob + offset, mac, sizeof(mac));
  offset += sizeof(mac);
  /* Cleanup the buffers. */
  memwipe(salt, 0, sizeof(salt));
  memwipe(encrypted, 0, encrypted_len);
  tor_free(encrypted);
  /* Extra precaution. */
  tor_assert(offset == final_blob_len);

  *encrypted_out = final_blob;
  return final_blob_len;
}

/* Take care of encoding the encrypted data section from the plaintext
 * creation buffer to actually encrypting it with the descriptor's key. A
 * newly allocated NULL terminated string containing the encoded encrypted
 * blob is put in encrypted_blob_out. Return 0 on success else a negative
 * value. */
static int
encode_encrypted_data(const hs_descriptor_t *desc,
                      char **encrypted_blob_out)
{
  int ret = -1;
  char *encoded_str, *line_str, *encrypted_blob;
  smartlist_t *lines = smartlist_new();

  tor_assert(desc);
  tor_assert(encrypted_blob_out);

  /* Build the start of the section prior to the introduction points. */
  {
    char *buf = encode_create2_list(desc->encrypted_data.create2_formats);
    if (buf == NULL) {
      log_err(LD_BUG, "HS desc doesn't have recognized handshake type.");
      goto err;
    }
    tor_asprintf(&line_str, "%s %s", str_create2_formats, buf);
    smartlist_add(lines, line_str);
    tor_free(buf);

    /* Put the required authentication line. */
    buf = smartlist_join_strings(desc->encrypted_data.auth_types, " ", 0,
                                 NULL);
    tor_asprintf(&line_str, "%s %s", str_auth_required, buf);
    tor_free(buf);
  }

  /* Build the introduction point(s) section. */
  SMARTLIST_FOREACH_BEGIN(desc->encrypted_data.intro_points,
                          const hs_desc_intro_point_t *, ip) {
    char *encoded_ip = encode_intro_point(ip);
    if (encoded_ip == NULL) {
      log_err(LD_BUG, "HS desc intro point is malformed.");
      goto err;
    }
    smartlist_add(lines, encoded_ip);
  } SMARTLIST_FOREACH_END(ip);

  /* Build the entire encrypted data section into one encoded plaintext and
   * then encrypt it. */
  encoded_str = smartlist_join_strings(lines, "\n", 0, NULL);

  /* Encrypt the section into an encrypted blob that we'll base64 encode
   * before returning it. */
  {
    char *enc_b64;
    ssize_t enc_b64_len, ret_len, enc_len;

    enc_len = encrypt_data(desc, encoded_str, &encrypted_blob);
    tor_free(encoded_str);
    /* Get the encoded size plus a NULL terminating byte. */
    enc_b64_len = base64_encode_size(enc_len, BASE64_ENCODE_MULTILINE) + 1;
    enc_b64 = tor_malloc_zero(enc_b64_len);
    /* Base64 the encrypted blob before returning it. */
    ret_len = base64_encode(enc_b64, enc_b64_len, encrypted_blob, enc_len,
                            BASE64_ENCODE_MULTILINE);
    /* Return length doesn't count the NULL byte. */
    tor_assert(ret_len == (enc_b64_len - 1));
    tor_free(encrypted_blob);
    *encrypted_blob_out = enc_b64;
  }
  /* Success! */
  ret = 0;

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  return ret;
}

/* Encode the given descriptor desc and on success encoded_out points
 * to a newly allocated NULl terminated string that contains the encoded
 * descriptor.
 *
 * Return 0 on success and encoded_out is a valid pointer. On error, -1 is
 * returned and encoded_out is untouched. */
int hs_desc_encode_descriptor(const hs_descriptor_t *desc,
                              char **encoded_out)
{
  int ret;
  char *encoded_str = NULL, *line_str;
  size_t encoded_len;
  smartlist_t *lines = smartlist_new();

  tor_assert(desc);
  tor_assert(encoded_out);

  /* Make sure we support the version of the descriptor format. */
  if (desc->plaintext_data.version != HS_DESC_SUPPORTED_FORMAT_VERSION) {
    ret = -1;
    goto err;
  }

  /* Build the non-encrypted values. */
  {
    char *encoded_cert;
    /* Encode certificate then create the first line of the descriptor. */
    ret = encode_cert(desc->plaintext_data.signing_key_cert,
                      &encoded_cert);
    if (ret < 0) {
      /* The function will print error logs. */
      goto err;
    }
    /* Create the hs descriptor line. */
    tor_asprintf(&line_str, "%s %" PRIu32, str_hs_desc,
                 desc->plaintext_data.version);
    smartlist_add(lines, line_str);
    /* Create the descriptor certificate line. */
    tor_asprintf(&line_str, "%s %s", str_desc_cert, encoded_cert);
    smartlist_add(lines, line_str);
    /* Create the revision counter line. */
    tor_asprintf(&line_str, "%s %" PRIu32, str_rev_counter,
                 desc->plaintext_data.revision_counter);
    smartlist_add(lines, line_str);
    tor_free(encoded_cert);
  }

  /* Build the encrypted data section. */
  {
    char *enc_b64_blob;
    ret = encode_encrypted_data(desc, &enc_b64_blob);
    if (ret < 0) {
      goto err;
    }
    tor_asprintf(&line_str,
                 "%s\n"
                 "-----BEGIN MESSAGE-----\n"
                 "%s"
                 "-----END MESSAGE-----",
                 str_encrypted, enc_b64_blob);
    smartlist_add(lines, line_str);
    tor_free(enc_b64_blob);
  }

  /* Join all lines in one string so we can generate a signature and append
   * it to the descriptor. */
  encoded_str = smartlist_join_strings(lines, "\n", 1, &encoded_len);

  /* Sign all fields of the descriptor with our short term signing key. */
  {
    ed25519_signature_t sig;
    char ed_sig_b64[ED25519_SIG_BASE64_LEN + 1];
    ret = ed25519_sign(&sig, (const uint8_t *) encoded_str, encoded_len,
                       &desc->plaintext_data.signing_kp);
    if (ret < 0) {
      log_warn(LD_BUG, "Can't sign encoded HS descriptor!");
      goto err;
    }
    ret = ed25519_signature_to_base64(ed_sig_b64, &sig);
    if (ret < 0) {
      log_warn(LD_BUG, "Can't base64 encode descriptor signature!");
      goto err;
    }
    /* Create the signature line. */
    tor_asprintf(&line_str, "%s %s", str_signature, ed_sig_b64);
    smartlist_add(lines, line_str);
  }
  /* Free previous string that we used so compute the signature. */
  tor_free(encoded_str);
  encoded_str = smartlist_join_strings(lines, "\n", 1, NULL);
  *encoded_out = encoded_str;

  /* XXX: Decode the generated descriptor as an extra validation. */

  /* XXX: Trigger a control port event. */

  /* Success! */
  ret = 0;

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  return ret;
}
