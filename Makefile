CC=		cc

CFLAGS=		-std=c99 \
		-pedantic \
		-Wall \
		-Wextra \
		-Wno-overlength-strings \
		-Wno-format \
		-Wno-unused-variable \
		-Wno-unused-but-set-variable \
		-D_DEFAULT_SOURCE \
		-g3 \
		-O2

CFLAGS_RELEASE=	-std=c99 \
		-pedantic \
		-Wall \
		-Wextra \
		-Werror \
		-Wno-overlength-strings \
		-Wno-sign-compare \
		-pedantic-errors \
		-D_DEFAULT_SOURCE \
		-O2

LDFLAGS=	-lpthread

SRC=		apathy.c
BIN=		apathy

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

release: CFLAGS = $(CFLAGS_RELEASE)
release: $(BIN)

clean:
	rm -f $(BIN)
