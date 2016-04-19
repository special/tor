/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_descriptor.c
 * \brief Test hidden service descriptor encoding and decoding.
 */

#define HS_DESCRIPTOR_PRIVATE

#include "crypto_ed25519.h"
#include "ed25519_cert.h"
#include "or.h"
#include "hs_descriptor.h"
#include "test.h"
#include "torcert.h"

static hs_desc_intro_point_t *
helper_build_intro_point(const ed25519_keypair_t *blinded_kp, time_t now,
                         const char *addr)
{
  int ret;
  ed25519_keypair_t auth_kp;
  hs_desc_intro_point_t *intro_point = NULL;
  hs_desc_intro_point_t *ip = tor_malloc_zero(sizeof(*ip));
  ip->link_specifiers = smartlist_new();

  {
    hs_desc_link_specifier_t *ls = tor_malloc_zero(sizeof(*ls));
    tor_addr_parse(&ls->u.ap.addr, addr);
    ls->u.ap.port = 9001;
    smartlist_add(ip->link_specifiers, ls);
  }

  ret = ed25519_keypair_generate(&auth_kp, 0);
  tt_int_op(ret, ==, 0);
  ip->auth_key_cert = tor_cert_create(blinded_kp, CERT_TYPE_HS_IP_AUTH,
                                      &auth_kp.pubkey, now, 3600,
                                      CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(ip->auth_key_cert);
  ret = curve25519_keypair_generate(&ip->enc_key, 0);
  tt_int_op(ret, ==, 0);

  ip->enc_key_legacy = crypto_pk_new();
  tt_assert(ip->enc_key_legacy);
  ret = crypto_pk_generate_key(ip->enc_key_legacy);
  tt_int_op(ret, ==, 0);

  intro_point = ip;
 done:
  return intro_point;
}

/* Return a valid hs_descriptor_t object. */
static hs_descriptor_t *
helper_build_hs_desc(void)
{
  int ret;
  time_t now = time(NULL);
  hs_descriptor_t *descp = NULL, *desc = tor_malloc_zero(sizeof(*desc));

  desc->plaintext_data.version = HS_DESC_SUPPORTED_FORMAT_VERSION;
  ret = ed25519_keypair_generate(&desc->plaintext_data.signing_kp, 0);
  tt_int_op(ret, ==, 0);
  ret = ed25519_keypair_generate(&desc->plaintext_data.blinded_kp, 0);
  tt_int_op(ret, ==, 0);

  desc->plaintext_data.signing_key_cert =
    tor_cert_create(&desc->plaintext_data.blinded_kp,
                    CERT_TYPE_HS_DESC_SIGN,
                    &desc->plaintext_data.signing_kp.pubkey, now,
                    3600,
                    CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(desc->plaintext_data.signing_key_cert);
  desc->plaintext_data.revision_counter = 42;

  /* Setup encrypted data section. */
  desc->encrypted_data.create2_ntor = 1;
  desc->encrypted_data.auth_types = smartlist_new();
  smartlist_add(desc->encrypted_data.auth_types, strdup("ed25519"));
  desc->encrypted_data.intro_points = smartlist_new();
  /* Add three intro points. */
  smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&desc->plaintext_data.blinded_kp, now,
                                         "1.2.3.4"));
  smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&desc->plaintext_data.blinded_kp, now,
                                         "4.3.2.1"));
  smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&desc->plaintext_data.blinded_kp, now,
                                         "3.2.1.4"));

  descp = desc;
 done:
  return descp;
}

static void
helper_compare_hs_desc(const hs_descriptor_t *desc1,
                       const hs_descriptor_t *desc2)
{
  // hs_desc_plaintext_data_t
  tt_int_op(desc1->plaintext_data.version, ==, desc2->plaintext_data.version);
  tt_assert(tor_cert_eq(desc1->plaintext_data.signing_key_cert,
                        desc2->plaintext_data.signing_key_cert));
  tt_mem_op(desc1->plaintext_data.signing_kp.pubkey.pubkey, OP_EQ,
            desc2->plaintext_data.signing_kp.pubkey.pubkey,
            ED25519_PUBKEY_LEN);
  tt_mem_op(desc1->plaintext_data.blinded_kp.pubkey.pubkey, OP_EQ,
            desc2->plaintext_data.blinded_kp.pubkey.pubkey,
            ED25519_PUBKEY_LEN);
  tt_uint_op(desc1->plaintext_data.revision_counter, ==,
             desc2->plaintext_data.revision_counter);

  // XXX encrypted_blob? not currently defined in the encoding-side descriptor

  // hs_desc_encrypted_data_t
  tt_uint_op(desc1->encrypted_data.create2_ntor, ==,
             desc2->encrypted_data.create2_ntor);

  // auth_types
  tt_int_op(!!desc1->encrypted_data.auth_types, ==,
            !!desc2->encrypted_data.auth_types);
  if (desc1->encrypted_data.auth_types && desc2->encrypted_data.auth_types) {
    int i;
    tt_int_op(smartlist_len(desc1->encrypted_data.auth_types), ==,
              smartlist_len(desc2->encrypted_data.auth_types));
    for (i = 0; i < smartlist_len(desc1->encrypted_data.auth_types); i++) {
      tt_str_op(smartlist_get(desc1->encrypted_data.auth_types, i), OP_EQ,
                smartlist_get(desc2->encrypted_data.auth_types, i));
    }
  }

  // intro_points
  {
    int i, j;
    tt_assert(desc1->encrypted_data.intro_points);
    tt_assert(desc2->encrypted_data.intro_points);
    tt_int_op(smartlist_len(desc1->encrypted_data.intro_points), ==,
              smartlist_len(desc2->encrypted_data.intro_points));
    for (i = 0; i < smartlist_len(desc1->encrypted_data.intro_points); i++) {
      hs_desc_intro_point_t *ip1 = smartlist_get(desc1->encrypted_data
                                                 .intro_points, i),
                            *ip2 = smartlist_get(desc2->encrypted_data
                                                 .intro_points, i);
      tt_assert(tor_cert_eq(ip1->auth_key_cert, ip2->auth_key_cert));
      tt_mem_op(ip1->enc_key.pubkey.public_key, OP_EQ,
                ip2->enc_key.pubkey.public_key,
                CURVE25519_PUBKEY_LEN);
      tt_assert(crypto_pk_cmp_keys(ip1->enc_key_legacy, ip2->enc_key_legacy)
                == 0);

      tt_int_op(smartlist_len(ip1->link_specifiers), ==,
                smartlist_len(ip2->link_specifiers));
      for (j = 0; j < smartlist_len(ip1->link_specifiers); j++) {
        hs_desc_link_specifier_t *ls1 = smartlist_get(ip1->link_specifiers, j),
                                 *ls2 = smartlist_get(ip2->link_specifiers, j);
        tt_int_op(ls1->type, ==, ls2->type);
        switch (ls1->type) {
          case LS_IPV4:
          case LS_IPV6:
            {
              char *addr1 = tor_addr_to_str_dup(&ls1->u.ap.addr),
                   *addr2 = tor_addr_to_str_dup(&ls2->u.ap.addr);
              tt_str_op(addr1, OP_EQ, addr2);
              tor_free(addr1);
              tor_free(addr2);
              tt_int_op(ls1->u.ap.port, ==, ls2->u.ap.port);
            }
            break;
          case LS_LEGACY_ID:
            tt_mem_op(ls1->u.legacy_id, OP_EQ, ls2->u.legacy_id,
                      sizeof(ls1->u.legacy_id));
            break;
          default:
            tt_assert(0);
        }
      }
    }
  }

 done:
  ;
}

/* Test certificate encoding put in a descriptor. */
static void
test_cert_encoding(void *arg)
{
  int ret;
  char *encoded = NULL;
  time_t now = time(NULL);
  ed25519_keypair_t kp;
  ed25519_public_key_t signed_key;
  ed25519_secret_key_t secret_key;
  tor_cert_t *cert = NULL;

  (void) arg;

  ret = ed25519_keypair_generate(&kp, 0);
  tt_int_op(ret, == , 0);
  ret = ed25519_secret_key_generate(&secret_key, 0);
  tt_int_op(ret, == , 0);
  ret = ed25519_public_key_generate(&signed_key, &secret_key);
  tt_int_op(ret, == , 0);

  /* XXX: Change cert type to the HS type 0x08. */
  cert = tor_cert_create(&kp, CERT_TYPE_SIGNING_AUTH, &signed_key,
                         now, 3600 * 2, CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(cert);

  /* Test the certificate encoding function. */
  ret = encode_cert(cert, &encoded);
  tt_int_op(ret, ==, 0);

  /* Validated the certificate string. */
  {
    char *end, *pos = encoded;
    char *b64_cert, buf[256];
    size_t b64_cert_len;
    tor_cert_t *parsed_cert;

    tt_int_op(strcmpstart(pos, "identity-ed25519\n"), ==, 0);
    pos += strlen("identity-ed25519\n");
    tt_int_op(strcmpstart(pos, "-----BEGIN ED25519 CERT-----\n"), ==, 0);
    pos += strlen("-----BEGIN ED25519 CERT-----\n");

    /* Isolate the base64 encoded certificate and try to decode it. */
    end = strstr(pos, "-----END ED25519 CERT-----");
    tt_assert(end);
    b64_cert = pos;
    b64_cert_len = end - pos;
    ret = base64_decode(buf, sizeof(buf), b64_cert, b64_cert_len);
    tt_int_op(ret, >, 0);
    /* Parseable? */
    parsed_cert = tor_cert_parse((uint8_t *) buf, ret);
    tt_assert(parsed_cert);
    /* Signature is valid? */
    ret = tor_cert_checksig(parsed_cert, &kp.pubkey, now + 10);
    tt_int_op(ret, ==, 0);
    ret = tor_cert_eq(cert, parsed_cert);
    tt_int_op(ret, ==, 1);
    /* The cert did have the signing key? */
    ret= ed25519_pubkey_eq(&parsed_cert->signing_key, &kp.pubkey);
    tt_int_op(ret, ==, 1);
    tor_cert_free(parsed_cert);

    /* Get to the end part of the certificate. */
    pos += b64_cert_len;
    tt_int_op(strcmpstart(pos, "-----END ED25519 CERT-----"), ==, 0);
    pos += strlen("-----END ED25519 CERT-----");
  }

 done:
  tor_cert_free(cert);
  free(encoded);
}

static void
test_link_specifier(void *arg)
{
  ssize_t ret;
  hs_desc_link_specifier_t spec;
  smartlist_t *link_specifiers = smartlist_new();

  (void) arg;

  /* Always this port. */
  spec.u.ap.port = 42;
  smartlist_add(link_specifiers, &spec);

  /* Test IPv4 for starter. */
  {
    char *b64, buf[256];
    uint32_t ipv4;
    link_specifier_t *ls;

    spec.type = LS_IPV4;
    ret = tor_addr_parse(&spec.u.ap.addr, "1.2.3.4");
    tt_int_op(ret, ==, AF_INET);
    b64 = encode_link_specifiers(link_specifiers);
    tt_assert(b64);

    /* Decode it and validate the format. */
    ret = base64_decode(buf, sizeof(buf), b64, strlen(b64));
    tt_int_op(ret, >, 0);
    /* First byte is the number of link specifier. */
    tt_int_op(get_uint8(buf), ==, 1);
    ret = link_specifier_parse(&ls, (uint8_t *) buf + 1, ret - 1);
    tt_int_op(ret, ==, 8);
    /* Should be 2 bytes for port and 4 bytes for IPv4. */
    tt_int_op(link_specifier_get_ls_len(ls), ==, 6);
    ipv4 = link_specifier_get_un_ipv4_addr(ls);
    tt_int_op(tor_addr_to_ipv4h(&spec.u.ap.addr), ==, ipv4);
    tt_int_op(link_specifier_get_un_ipv4_port(ls), ==, spec.u.ap.port);

    link_specifier_free(ls);
    tor_free(b64);
  }

  /* Test IPv6. */
  {
    char *b64, buf[256];
    uint8_t ipv6[16];
    link_specifier_t *ls;

    spec.type = LS_IPV6;
    ret = tor_addr_parse(&spec.u.ap.addr, "[1:2:3:4::]");
    tt_int_op(ret, ==, AF_INET6);
    b64 = encode_link_specifiers(link_specifiers);
    tt_assert(b64);

    /* Decode it and validate the format. */
    ret = base64_decode(buf, sizeof(buf), b64, strlen(b64));
    tt_int_op(ret, >, 0);
    /* First byte is the number of link specifier. */
    tt_int_op(get_uint8(buf), ==, 1);
    ret = link_specifier_parse(&ls, (uint8_t *) buf + 1, ret - 1);
    tt_int_op(ret, ==, 20);
    /* Should be 2 bytes for port and 16 bytes for IPv6. */
    tt_int_op(link_specifier_get_ls_len(ls), ==, 18);
    for (unsigned int i = 0; i < sizeof(ipv6); i++) {
      ipv6[i] = link_specifier_get_un_ipv6_addr(ls, i);
    }
    tt_mem_op(tor_addr_to_in6_addr8(&spec.u.ap.addr), ==, ipv6, sizeof(ipv6));
    tt_int_op(link_specifier_get_un_ipv6_port(ls), ==, spec.u.ap.port);

    link_specifier_free(ls);
    tor_free(b64);
  }

 done:
  return;
}

static void
test_encode_descriptor(void *arg)
{
  int ret;
  char *encoded = NULL;
  hs_descriptor_t *desc = helper_build_hs_desc();

  (void) arg;

  ret = hs_desc_encode_descriptor(desc, &encoded);
  tt_int_op(ret, ==, 0);
  tt_assert(encoded);

 done:
  hs_descriptor_free(desc);
  tor_free(encoded);
}

static void
test_decode_descriptor(void *arg)
{
  int ret;
  char *encoded = NULL;
  hs_descriptor_t *desc = helper_build_hs_desc();
  hs_descriptor_t *decoded = NULL;

  (void) arg;

  ret = hs_desc_encode_descriptor(desc, &encoded);
  tt_int_op(ret, ==, 0);
  tt_assert(encoded);

  ret = hs_desc_decode_descriptor(encoded, NULL, &decoded);
  tt_int_op(ret, ==, 0);
  tt_assert(decoded);

  helper_compare_hs_desc(desc, decoded);
 done:
  hs_descriptor_free(desc);
  hs_descriptor_free(decoded);
  tor_free(encoded);
}

struct testcase_t hs_descriptor[] = {
  { "cert_encoding", test_cert_encoding, TT_FORK,
    NULL, NULL },
  { "link_specifier", test_link_specifier, TT_FORK,
    NULL, NULL },
  { "encode_descriptor", test_encode_descriptor, TT_FORK,
    NULL, NULL },
  { "decode_descriptor", test_decode_descriptor, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};
