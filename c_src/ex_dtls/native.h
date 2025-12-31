#pragma once

#include "dtls.h"
#include <erl_nif.h>

typedef struct State State;

struct State {
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  EVP_PKEY *pkey;
  X509 *x509;
  int mode;
  int hsk_finished;
  int closed;
};
