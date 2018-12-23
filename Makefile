CC=		clang

CFLAGS=		-std=c99 \
		-Wall \
		-Wextra \
		-Wno-overlength-strings \
		-Wno-format \
		-Wno-unused-variable \
		-D_DEFAULT_SOURCE \
		-DHASH_DEBUG=1 \
		-g3 \
		-gdwarf-2 \
		-O2

CFLAGS_RELEASE=	-std=c99 \
		-Wall \
		-Wextra \
		-Werror \
		-Wno-overlength-strings \
		-Wno-sign-compare \
		-D_DEFAULT_SOURCE \
		-O2

LDFLAGS=	-lpthread

SRC=		apathy.c
BIN=		apathy

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

profile: LDFLAGS += -lprofiler
profile: $(BIN)

release: CFLAGS = $(CFLAGS_RELEASE)
release: $(BIN)

clean:
	rm -f $(BIN)
