CC=		clang
AFL_CC=		afl-clang

CFLAGS=		-std=c99 \
		-Wall \
		-Wextra \
		-D_DEFAULT_SOURCE \
		-O2

LDFLAGS=	-lm -lpthread

SRC=		apathy.c \
		debug.c \
		dot.c \
		field.c \
		file_view.c \
		hash.c \
		path_graph.c \
		regex.c \
		request.c \
		session.c \
		time.c \
		truncate.c

BIN=		apathy

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN)

release: CFLAGS = $(CFLAGS_RELEASE)
release: $(BIN)

profile: LDFLAGS += -lprofiler
profile: $(BIN)

afl-fuzz-access-logs: CC = $(AFL_CC)
afl-fuzz-access-logs: $(BIN)
	afl-fuzz -i afl/access_logs \
	         -o afl/access_log_findings \
	         ./$(BIN) -T afl/default/truncate_patterns.txt @@

afl-resume-access-logs: CC = $(AFL_CC)
afl-resume-access-logs: $(BIN)
	afl-fuzz -i - \
	         -o afl/access_log_findings \
	         ./$(BIN) -T afl/default/truncate_patterns.txt @@

afl-fuzz-truncate-patterns: CC = $(AFL_CC)
afl-fuzz-truncate-patterns: $(BIN)
	afl-fuzz -i afl/truncate_patterns \
	         -o afl/truncate_pattern_findings \
	         ./$(BIN) -T @@ afl/default/access.log

afl-resume-truncate-patterns: CC = $(AFL_CC)
afl-resume-truncate-patterns: $(BIN)
	afl-fuzz -i - \
	         -o afl/truncate_pattern_findings \
	         ./$(BIN) -T @@ afl/default/access.log
