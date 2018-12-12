CC=		cc

CFLAGS=		-ansi \
		-pedantic \
		-Wall \
		-Wextra \
		-Wno-overlength-strings \
		-Wno-format \
		-Wno-unused-variable \
		-Wno-unused-but-set-variable \
		-D_DEFAULT_SOURCE \
		-g \
		-O0

CFLAGS_RELEASE=	-ansi \
		-pedantic \
		-Wall \
		-Wextra \
		-Werror \
		-Wno-overlength-strings \
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
