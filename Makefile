DIR := c_src/ex_dtls
PRIV_DIR := $(MIX_APP_PATH)/priv
DTLS_SO := $(PRIV_DIR)/libdtls.so

SOURCES = $(DIR)/native.c $(DIR)/dtls.c $(DIR)/dyn_buff.c $(DIR)/bio_frag.c

CFLAGS += $(EXDTLS_DEBUG) -fPIC -shared
IFLAGS += -I$(ERTS_INCLUDE_DIR) -I$(DIR)
LDFLAGS += -lssl


all: $(DTLS_SO)

$(DTLS_SO): $(SOURCES)
	@mkdir -p $(PRIV_DIR)
	$(CC) $(CFLAGS) $(IFLAGS) $(LFLAGS) $(SOURCES) -o $(DTLS_SO) $(LDFLAGS)

format:
	clang-format -i $(DIR)/*.c $(DIR)/*.h

.PHONY: format
