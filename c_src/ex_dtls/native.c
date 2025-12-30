#include "native.h"

ErlNifResourceType *DTLS_RESOURCE_TYPE;

struct Datagram {
  ErlNifBinary *packet;
  struct Datagram *next;
};

int nif_get_string(ERL_NIF_TERM arg, char **data, int *size) {
  ErlNifBinary bin;
  if (!enif_inspect_binary(NULL, arg, &bin)) {
    return 0;
  }

  *size = bin.size;
  *data = (char *)malloc(bin.size + 1);
  memcpy(*data, bin.data, bin.size);
  (*data)[bin.size] = '\0';

  return 1;
}

int nif_get_atom(ERL_NIF_TERM arg, char **data, int *size) {
  if (!enif_get_atom_length(NULL, arg, size, ERL_NIF_LATIN1)) {
    return 0;
  }

  *data = (char *)malloc(*size + 1);
  if (!enif_get_atom(NULL, arg, *data, *size + 1, ERL_NIF_LATIN1)) {
    free(*data);
    return 0;
  }

  return 1;
}

ERL_NIF_TERM nif_raise(ErlNifEnv *env, const char *msg) {
  ERL_NIF_TERM err_reason = enif_make_string(env, msg, ERL_NIF_LATIN1);
  return enif_raise_exception(env, err_reason);
}

static void ssl_info_cb(const SSL *ssl, int where, int ret);
static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx);
static int read_pending_data(ErlNifBinary ***payloads, int *size, State *state);
static void cert_to_payload(ErlNifEnv *env, X509 *x509, ErlNifBinary *payload);
static void pkey_to_payload(ErlNifEnv *env, EVP_PKEY *pkey,
                            ErlNifBinary *payload);

ERL_NIF_TERM do_init(ErlNifEnv *env, char *mode, int dtls_srtp, int verify_peer,
                     EVP_PKEY *pkey, X509 *x509);
ERL_NIF_TERM handle_regular_read(ErlNifEnv *env, State *state, char data[],
                                 int ret);
ERL_NIF_TERM handle_read_error(ErlNifEnv *env, State *state, int ret);
ERL_NIF_TERM handle_handshake_in_progress(ErlNifEnv *env, State *state,
                                          int ret);
ERL_NIF_TERM handle_handshake_finished(ErlNifEnv *env, State *state);
static ErlNifBinary **dgram_to_payload_array(struct Datagram *dgram_list,
                                             int len);
static void free_payload_array(ErlNifBinary **payloads, int len);

ERL_NIF_TERM init(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  ERL_NIF_TERM res_term;
  ERL_NIF_TERM err_reason;

  if (argc != 3) {
    return enif_make_badarg(env);
  }

  char *mode_str = NULL;
  int dtls_srtp, verify_peer, mode_str_size;

  if (!nif_get_atom(argv[0], &mode_str, &mode_str_size)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[1], &dtls_srtp)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[2], &verify_peer)) {
    return enif_make_badarg(env);
  }

  EVP_PKEY *pkey = gen_key();
  if (pkey == NULL) {
    err_reason =
        enif_make_string(env, "Cannot generate key pair", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  X509 *x509 = gen_cert(pkey, -31536000L, 31536000L);
  if (x509 == NULL) {
    err_reason = enif_make_string(env, "Cannot generate cert", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  res_term = do_init(env, mode_str, dtls_srtp, verify_peer, pkey, x509);
exit:
  if (mode_str)
    free(mode_str);
  return res_term;
}

ERL_NIF_TERM init_from_key_cert(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[]) {
  ERL_NIF_TERM res_term;
  ERL_NIF_TERM err_reason;

  if (argc != 5) {
    return enif_make_badarg(env);
  }

  char *mode_str = NULL, *pkey = NULL, *cert = NULL;
  int mode_str_size, pkey_size, cert_size;
  int dtls_srtp, verify_peer;

  if (!nif_get_atom(argv[0], &mode_str, &mode_str_size)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[1], &dtls_srtp)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[2], &verify_peer)) {
    return enif_make_badarg(env);
  }

  if (!nif_get_string(argv[3], &pkey, &pkey_size)) {
    return enif_make_badarg(env);
  }

  if (!nif_get_string(argv[4], &cert, &cert_size)) {
    return enif_make_badarg(env);
  }

  EVP_PKEY *evp_pkey = decode_pkey(pkey, pkey_size);
  if (evp_pkey == NULL) {
    err_reason = enif_make_string(env, "Cannot decode pkey", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  X509 *x509 = decode_cert(cert, cert_size);
  if (x509 == NULL) {
    err_reason = enif_make_string(env, "Cannot decode cert", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  res_term = do_init(env, mode_str, dtls_srtp, verify_peer, evp_pkey, x509);
exit:
  if (mode_str)
    free(mode_str);
  if (pkey)
    free(pkey);
  if (cert)
    free(cert);
  return res_term;
}

ERL_NIF_TERM generate_key_cert(ErlNifEnv *env, int argc,
                               const ERL_NIF_TERM argv[]) {
  if (argc != 2) {
    return enif_make_badarg(env);
  }

  int not_before, not_after;

  if (!enif_get_int(env, argv[0], &not_before)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[1], &not_after)) {
    return enif_make_badarg(env);
  }

  ErlNifBinary pkey_payload;
  ErlNifBinary cert_payload;

  EVP_PKEY *pkey = gen_key();
  X509 *cert = gen_cert(pkey, (long)not_before, (long)not_after);

  pkey_to_payload(env, pkey, &pkey_payload);
  cert_to_payload(env, cert, &cert_payload);

  ERL_NIF_TERM pkey_term = enif_make_binary(env, &pkey_payload);
  ERL_NIF_TERM cert_term = enif_make_binary(env, &cert_payload);
  ERL_NIF_TERM res_term = enif_make_tuple2(env, pkey_term, cert_term);

  enif_release_binary(&pkey_payload);
  enif_release_binary(&cert_payload);
  return res_term;
}

ERL_NIF_TERM get_pkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  ErlNifBinary payload;
  pkey_to_payload(env, state->pkey, &payload);
  ERL_NIF_TERM res_term = enif_make_binary(env, &payload);
  enif_release_binary(&payload);
  return res_term;
}

ERL_NIF_TERM get_cert(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  ErlNifBinary payload;
  cert_to_payload(env, state->x509, &payload);
  ERL_NIF_TERM res_term = enif_make_binary(env, &payload);
  enif_release_binary(&payload);
  return res_term;
}

ERL_NIF_TERM get_peer_cert(ErlNifEnv *env, int argc,
                           const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM res_term;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  X509 *x509 = SSL_get0_peer_certificate(state->ssl);
#else
  X509 *x509 = SSL_get_peer_certificate(state->ssl);
#endif

  if (x509 != NULL) {
    ErlNifBinary payload;
    cert_to_payload(env, x509, &payload);
    res_term = enif_make_binary(env, &payload);
    enif_release_binary(&payload);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    X509_free(x509);
#endif

  } else {
    res_term = enif_make_atom(env, "nil");
  }

  return res_term;
}

ERL_NIF_TERM get_cert_fingerprint(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM res_term;
  ErlNifBinary cert;

  if (!enif_inspect_binary(env, argv[0], &cert)) {
    return enif_make_badarg(env);
  }

  unsigned char md[EVP_MAX_MD_SIZE] = {0};
  unsigned int size;

  X509 *x509 = decode_cert(cert.data, cert.size);
  if (x509 == NULL) {
    return nif_raise(env, "Cannot decode cert");
  }

  if (X509_digest(x509, EVP_sha256(), md, &size) != 1) {
    return nif_raise(env, "Can't get cert fingerprint");
  }
  ErlNifBinary payload;
  enif_alloc_binary(size, &payload);
  memcpy(payload.data, md, size);
  payload.size = size;
  res_term = enif_make_binary(env, &payload);
  enif_release_binary(&payload);
exit:
  return res_term;
}

ERL_NIF_TERM do_handshake(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  if (state->closed == 1) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "closed"));
  }

  SSL_do_handshake(state->ssl);

  ErlNifBinary **gen_packets = NULL;
  int gen_packets_size = 0;
  int ret = read_pending_data(&gen_packets, &gen_packets_size, state);

  if (ret == 0 && gen_packets == NULL) {
    return nif_raise(env, "Handshake failed: no packets generated");
  } else if (ret < 0) {
    return nif_raise(env, "Handshake failed: couldn't read pending data");
  } else {
    int timeout = get_timeout(state->ssl);

    ERL_NIF_TERM list = enif_make_list(env, 0);
    for (int i = gen_packets_size - 1; i >= 0; i--) {
      list =
          enif_make_list_cell(env, enif_make_binary(env, gen_packets[i]), list);
    }

    ERL_NIF_TERM res_term = enif_make_tuple3(env, enif_make_atom(env, "ok"),
                                             list, enif_make_int(env, timeout));
    free_payload_array(gen_packets, gen_packets_size);
    return res_term;
  }
}

ERL_NIF_TERM write_data(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  if (argc != 2) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  ErlNifBinary payload;
  if (!enif_inspect_binary(env, argv[1], &payload)) {
    return enif_make_badarg(env);
  }

  if (state->closed == 1) {
    DEBUG("Cannot write, connection closed");
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "closed"));
  }

  if (state->hsk_finished != 1) {
    DEBUG("Cannot write, handshake not finished");
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "handshake_not_finished"));
  }

  int ret = SSL_write(state->ssl, payload.data, payload.size);
  if (ret <= 0) {
    DEBUG("Unable to write data");
    return nif_raise(env, "Unable to write data");
  }

  DEBUG("Wrote %d bytes of data", ret);

  BIO *wbio = SSL_get_wbio(state->ssl);
  size_t pending_data_len = BIO_ctrl_pending(wbio);
  if (pending_data_len == 0) {
    DEBUG("No data to read from BIO after writing");
    return nif_raise(env, "No data to read from BIO after writing");
  }

  ErlNifBinary **gen_packets = NULL;
  int gen_packets_size = 0;
  read_pending_data(&gen_packets, &gen_packets_size, state);
  if (gen_packets == NULL) {
    DEBUG("Couldn't read pending data after writing");
    return nif_raise(env, "Couldn't read pending data after writing");
  }

  ERL_NIF_TERM list = enif_make_list(env, 0);
  for (int i = gen_packets_size - 1; i >= 0; i--) {
    list =
        enif_make_list_cell(env, enif_make_binary(env, gen_packets[i]), list);
  }

  ERL_NIF_TERM res_term =
      enif_make_tuple2(env, enif_make_atom(env, "ok"), list);
  free_payload_array(gen_packets, gen_packets_size);

  return res_term;
}

ERL_NIF_TERM handle_data(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  if (argc != 2) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  ErlNifBinary payload;
  if (!enif_inspect_binary(env, argv[1], &payload)) {
    return enif_make_badarg(env);
  }

  if (state->closed == 1) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "closed"));
  }

  if (payload.size != 0) {
    DEBUG("Feeding: %d", payload.size);

    int bytes = BIO_write(SSL_get_rbio(state->ssl), payload.data, payload.size);
    if (bytes <= 0) {
      DEBUG("RBIO: write error");
      return nif_raise(env, "Handshake failed: read BIO error");
    }

    DEBUG("RBIO: wrote %d", bytes);
  }

  char data[1500] = {0};
  int ret = SSL_read(state->ssl, &data, 1500);

  if (state->hsk_finished == 1) {
    return handle_regular_read(env, state, data, ret);
  } else if (SSL_is_init_finished(state->ssl) == 1) {
    DEBUG("Handshake finished successfully");
    return handle_handshake_finished(env, state);
  } else {
    DEBUG("Handshake in progress");
    return handle_handshake_in_progress(env, state, ret);
  }
}

ERL_NIF_TERM do_init(ErlNifEnv *env, char *mode_str, int dtls_srtp,
                     int verify_peer, EVP_PKEY *pkey, X509 *x509) {
  ERL_NIF_TERM res_term;
  ERL_NIF_TERM err_reason;

  State *state = enif_alloc_resource(DTLS_RESOURCE_TYPE, sizeof(State));
  state->ssl_ctx = NULL;
  state->ssl = NULL;
  state->pkey = NULL;
  state->x509 = NULL;
  state->mode = 0;
  state->hsk_finished = 0;
  state->closed = 0;

  int mode;
  if (strcmp(mode_str, "client") == 0) {
    mode = MODE_CLIENT;
  } else if (strcmp(mode_str, "server") == 0) {
    mode = MODE_SERVER;
  } else {
    err_reason = enif_make_string(env, "Invalid DTLS mode", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }
  state->mode = mode;

  state->ssl_ctx = create_ctx(dtls_srtp);
  if (state->ssl_ctx == NULL) {
    err_reason = enif_make_string(env, "Cannot create ssl_ctx", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  if (verify_peer == 1) {
    SSL_CTX_set_verify(state->ssl_ctx,
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER,
                       verify_cb);
  }

  state->pkey = pkey;
  if (SSL_CTX_use_PrivateKey(state->ssl_ctx, state->pkey) != 1) {
    err_reason =
        enif_make_string(env, "Cannot set private key", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  state->x509 = x509;
  if (SSL_CTX_use_certificate(state->ssl_ctx, state->x509) != 1) {
    err_reason = enif_make_string(env, "Cannot set cert", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  state->ssl = create_ssl(state->ssl_ctx, state->mode);
  if (state->ssl == NULL) {
    err_reason = enif_make_string(env, "Cannot create ssl", ERL_NIF_LATIN1);
    res_term = enif_raise_exception(env, err_reason);
    goto exit;
  }

  state->hsk_finished = 0;
  SSL_set_info_callback(state->ssl, ssl_info_cb);
  res_term = enif_make_resource(env, state);

exit:
  enif_release_resource(state);
  return res_term;
}

// prefix close with exd (ex_dtls) as close is defined in unistd.h
ERL_NIF_TERM exd_close(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  if (state->closed == 1) {
    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                            enif_make_list(env, 0));
  }

  state->closed = 1;
  if (SSL_shutdown(state->ssl) < 0) {
    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                            enif_make_list(env, 0));
  } else {
    ErlNifBinary **gen_packets = NULL;
    int gen_packets_size = 0;
    read_pending_data(&gen_packets, &gen_packets_size, state);

    if (gen_packets == NULL) {
      return nif_raise(env, "Close failed: couldn't read pending data");
    } else {
      ERL_NIF_TERM list = enif_make_list(env, 0);
      for (int i = gen_packets_size - 1; i >= 0; i--) {
        list = enif_make_list_cell(env, enif_make_binary(env, gen_packets[i]),
                                   list);
      }

      ERL_NIF_TERM res_term =
          enif_make_tuple2(env, enif_make_atom(env, "ok"), list);
      free_payload_array(gen_packets, gen_packets_size);
      return res_term;
    }
  }
}

ERL_NIF_TERM handle_regular_read(ErlNifEnv *env, State *state, char data[],
                                 int ret) {
  if (ret > 0) {
    ErlNifBinary packets;
    enif_alloc_binary(ret, &packets);
    memcpy(packets.data, data, ret);
    packets.size = (unsigned int)ret;
    ERL_NIF_TERM res_term = enif_make_tuple2(env, enif_make_atom(env, "ok"),
                                             enif_make_binary(env, &packets));
    enif_release_binary(&packets);
    return res_term;
  }

  return handle_read_error(env, state, ret);
}

ERL_NIF_TERM handle_read_error(ErlNifEnv *env, State *state, int ret) {
  // handle READ errors including DTLS alerts
  int error = SSL_get_error(state->ssl, ret);
  switch (error) {
  case SSL_ERROR_ZERO_RETURN:
    state->closed = 1;
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "peer_closed_for_writing"));
  case SSL_ERROR_WANT_READ:
    DEBUG("SSL WANT READ. This is workaround. Did we get retransmission?");
    return enif_make_atom(env, "handshake_want_read");
  default:
    DEBUG("SSL ERROR. Code: %d, desc: %s", error,
          ERR_reason_error_string(ERR_get_error()));
    if (state->hsk_finished == 0) {
      // If handshake is in-progress, return handshake error.
      // Otherwise, we failed when trying to decrypt data.
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "handshake_error"));
    } else {
      return nif_raise(env, "SSL read error");
    }
  }
}

ERL_NIF_TERM handle_handshake_finished(ErlNifEnv *env, State *state) {
  ERL_NIF_TERM res_term;
  ErlNifBinary **gen_packets = NULL;
  int gen_packets_size = 0;
  KeyingMaterial *keying_material = export_keying_material(state->ssl);
  if (keying_material == NULL) {
    DEBUG("Cannot export keying material");
    return nif_raise(env, "Handshake failed: cannot export keying material");
  }

  int len = keying_material->len;
  ErlNifBinary client_keying_material;
  enif_alloc_binary(len, &client_keying_material);
  memcpy(client_keying_material.data, keying_material->client, len);
  client_keying_material.size = len;

  ErlNifBinary server_keying_material;
  enif_alloc_binary(len, &server_keying_material);
  memcpy(server_keying_material.data, keying_material->server, len);
  server_keying_material.size = len;

  int ret = read_pending_data(&gen_packets, &gen_packets_size, state);
  if (ret < 0) {
    res_term = nif_raise(env, "Handshake failed: couldn't read pending data.");
    goto cleanup;
  }

  state->hsk_finished = 1;

  ErlNifBinary *local_keying_material;
  ErlNifBinary *remote_keying_material;

  if (state->mode == MODE_CLIENT) {
    local_keying_material = &client_keying_material;
    remote_keying_material = &server_keying_material;
  } else {
    local_keying_material = &server_keying_material;
    remote_keying_material = &client_keying_material;
  }

  ERL_NIF_TERM list = enif_make_list(env, 0);
  for (int i = gen_packets_size - 1; i >= 0; i--) {
    list =
        enif_make_list_cell(env, enif_make_binary(env, gen_packets[i]), list);
  }

  res_term = enif_make_tuple5(
      env, enif_make_atom(env, "handshake_finished"),
      enif_make_binary(env, local_keying_material),
      enif_make_binary(env, remote_keying_material),
      enif_make_int(env, keying_material->protection_profile), list);

cleanup:
  free_payload_array(gen_packets, gen_packets_size);
  enif_release_binary(&client_keying_material);
  enif_release_binary(&server_keying_material);
  return res_term;
}

ERL_NIF_TERM handle_handshake_in_progress(ErlNifEnv *env, State *state,
                                          int ret) {
  int ssl_error = SSL_get_error(state->ssl, ret);
  switch (ssl_error) {
  case SSL_ERROR_WANT_READ:
    DEBUG("SSL WANT READ");
    ErlNifBinary **gen_packets = NULL;
    int gen_packets_size = 0;
    int read_err = read_pending_data(&gen_packets, &gen_packets_size, state);

    if (read_err < 0) {
      return nif_raise(env, "Handshake failed: couldn't read pending data");
    } else if (read_err == 0 && gen_packets == NULL) {
      return enif_make_atom(env, "handshake_want_read");
    } else {
      int timeout = get_timeout(state->ssl);
      ERL_NIF_TERM list = enif_make_list(env, 0);
      for (int i = gen_packets_size - 1; i >= 0; i--) {
        list = enif_make_list_cell(env, enif_make_binary(env, gen_packets[i]),
                                   list);
      }

      ERL_NIF_TERM res_term =
          enif_make_tuple3(env, enif_make_atom(env, "handshake_packets"), list,
                           enif_make_int(env, timeout));

      free_payload_array(gen_packets, gen_packets_size);

      return res_term;
    }
  default:
    return handle_read_error(env, state, ret);
  }
}

ERL_NIF_TERM handle_timeout(ErlNifEnv *env, int argc,
                            const ERL_NIF_TERM argv[]) {
  if (argc != 1) {
    return enif_make_badarg(env);
  }

  State *state;
  if (!enif_get_resource(env, argv[0], DTLS_RESOURCE_TYPE, (void **)&state)) {
    return enif_make_badarg(env);
  }

  if (state->closed == 1) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "closed"));
  }

  long result = DTLSv1_handle_timeout(state->ssl);
  if (result != 1)
    return enif_make_atom(env, "ok");

  ErlNifBinary **gen_packets = NULL;
  int gen_packets_size = 0;
  read_pending_data(&gen_packets, &gen_packets_size, state);

  if (gen_packets == NULL) {
    return nif_raise(env,
                     "Retransmit handshake failed: couldn't read pending data");
  } else {
    int timeout = get_timeout(state->ssl);
    ERL_NIF_TERM list = enif_make_list(env, 0);
    for (int i = gen_packets_size - 1; i >= 0; i--) {
      list =
          enif_make_list_cell(env, enif_make_binary(env, gen_packets[i]), list);
    }

    ERL_NIF_TERM res_term =
        enif_make_tuple3(env, enif_make_atom(env, "retransmit"), list,
                         enif_make_int(env, timeout));

    free_payload_array(gen_packets, gen_packets_size);
    return res_term;
  }
}

static void ssl_info_cb(const SSL *ssl, int where, int ret) {
  if (where & SSL_CB_ALERT) {
    const char *type = SSL_alert_type_string(ret);
    const char *type_long = SSL_alert_type_string_long(ret);
    const char *desc = SSL_alert_desc_string(ret);
    const char *desc_long = SSL_alert_desc_string_long(ret);

    // UNIFEX_MAYBE_UNUSED(type);
    // UNIFEX_MAYBE_UNUSED(type_long);
    // UNIFEX_MAYBE_UNUSED(desc);
    // UNIFEX_MAYBE_UNUSED(desc_long);

    DEBUG("DTLS alert occurred, where: %d, ret: %d, type: %s, type_long: %s, "
          "desc: %s, desc_long: %s",
          where, ret, type, type_long, desc, desc_long);
  }
}

static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  int err = X509_STORE_CTX_get_error(ctx);

  if (err == X509_V_ERR_CERT_HAS_EXPIRED) {
    // decline expired certs
    return 0;
  } else if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
    // accept self-signed certs
    return 1;
  } else {
    return preverify_ok;
  }
}

static int read_pending_data(ErlNifBinary ***payloads, int *size,
                             State *state) {

  struct Datagram *dgram_list = NULL;
  struct Datagram *itr = NULL;
  *size = 0;

  size_t pending_data_len = 0;
  while ((pending_data_len = BIO_ctrl_pending(SSL_get_wbio(state->ssl))) > 0) {
    DEBUG("WBIO: pending data: %ld bytes", pending_data_len);
    struct Datagram *dgram = calloc(1, sizeof(struct Datagram));
    ErlNifBinary *payload = calloc(1, sizeof(ErlNifBinary));
    enif_alloc_binary(pending_data_len, payload);
    dgram->packet = payload;
    dgram->next = NULL;

    BIO *wbio = SSL_get_wbio(state->ssl);
    int read_bytes = BIO_read(wbio, payload->data, pending_data_len);
    if (read_bytes <= 0) {
      DEBUG("WBIO: read error");
      free(dgram);
      enif_release_binary(payload);
      free(payload);

      struct Datagram *ptr = dgram_list;

      if (ptr != NULL) {
        if (ptr->next == NULL) {
          enif_release_binary(ptr->packet);
          free(ptr->packet);
          free(ptr);
        } else {
          struct Datagram *next = ptr->next;
          while (next != NULL) {
            enif_release_binary(ptr->packet);
            free(ptr->packet);
            free(ptr);
            ptr = next;
            next = ptr->next;
          }
        }
      }

      *size = 0;
      *payloads = NULL;
      return -1;
    } else {
      DEBUG("WBIO: read: %d bytes", read_bytes);
      dgram->packet->size = (unsigned int)pending_data_len;
    }

    if (dgram_list == NULL) {
      dgram_list = dgram;
      itr = dgram_list;
    } else {
      itr->next = dgram;
      itr = itr->next;
    }

    (*size)++;
  }

  *payloads = dgram_to_payload_array(dgram_list, *size);
  return 0;
}

static ErlNifBinary **dgram_to_payload_array(struct Datagram *dgram_list,
                                             int len) {
  if (len == 0) {
    return NULL;
  }

  ErlNifBinary **payloads = calloc(len, sizeof(ErlNifBinary *));

  struct Datagram *itr = dgram_list;

  for (int i = 0; i < len; i++) {
    payloads[i] = itr->packet;
    itr = itr->next;
  }

  itr = dgram_list;
  struct Datagram *next = dgram_list->next;

  if (next == NULL) {
    free(itr);
  } else {
    while (next != NULL) {
      free(itr);
      itr = next;
      next = itr->next;
    }
  }

  return payloads;
}

static void free_payload_array(ErlNifBinary **payloads, int len) {
  if (payloads == NULL) {
    return;
  }

  for (int i = 0; i < len; i++) {
    enif_release_binary(payloads[i]);
    free(payloads[i]);
  }
  free(payloads);
}

static void pkey_to_payload(ErlNifEnv *env, EVP_PKEY *pkey,
                            ErlNifBinary *payload) {
  int len = i2d_PrivateKey(pkey, NULL);
  enif_alloc_binary(len, payload);
  unsigned char *p = payload->data;
  i2d_PrivateKey(pkey, &p);
  payload->size = len;
}

static void cert_to_payload(ErlNifEnv *env, X509 *x509, ErlNifBinary *payload) {
  int len = i2d_X509(x509, NULL);
  enif_alloc_binary(len, payload);
  unsigned char *p = payload->data;
  i2d_X509(x509, &p);
  payload->size = len;
}

void dtls_state_dtor(ErlNifEnv *env, void *obj) {
  State *state = (State *)obj;
  if (state->ssl) {
    SSL_free(state->ssl);
  }
  if (state->ssl_ctx) {
    SSL_CTX_free(state->ssl_ctx);
  }
  if (state->pkey) {
    EVP_PKEY_free(state->pkey);
  }
  if (state->x509) {
    X509_free(state->x509);
  }
}

static ErlNifFunc nif_funcs[] = {
    {"init", 3, init},
    {"init_from_key_cert", 5, init_from_key_cert},
    {"generate_key_cert", 2, generate_key_cert, ERL_DIRTY_JOB_CPU_BOUND},
    {"get_pkey", 1, get_pkey},
    {"get_cert", 1, get_cert},
    {"get_peer_cert", 1, get_peer_cert},
    {"get_cert_fingerprint", 1, get_cert_fingerprint},
    {"do_handshake", 1, do_handshake},
    {"handle_timeout", 1, handle_timeout},
    {"write_data", 2, write_data},
    {"handle_data", 2, handle_data},
    {"exd_close", 1, exd_close},
};

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
  DTLS_RESOURCE_TYPE =
      enif_open_resource_type(env, NULL, "dtls_state", dtls_state_dtor,
                              ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
#ifdef _WIN32
  srand((unsigned int)time(NULL));
#else
  FILE *urandom = fopen("/dev/urandom", "r");
  if (urandom == NULL) {
    DEBUG("Cannot open /dev/urandom");
    return -1;
  }
  
  unsigned int seed;
  int bytes = fread(&seed, sizeof(unsigned int), 1, urandom);
  if (bytes != 1) {
    DEBUG("Cannot read random bytes from /dev/urandom");
    return -1;
  }
    
  DEBUG("Random seed: %u\n", seed);
    
  srand(seed);
#endif
  return 0;
}

ERL_NIF_INIT(Elixir.ExDTLS.Native, nif_funcs, &load, NULL, NULL, NULL);