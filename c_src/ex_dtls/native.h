#pragma once

#include <erl_nif.h>
#include "dtls.h"

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
