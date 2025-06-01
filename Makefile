CC = g++
CC2 = gcc
CFLAGS = -Wall

SRCDIR = src
BUILDDIR = build

TESTDIR = test_prog
TESTBUILDDIR = test_bin

# TARGET = $(BUILDDIR)/a.out
TARGET = fuzzer

SRCS = $(wildcard $(SRCDIR)/*.cc)
OBJS = $(patsubst $(SRCDIR)/%.cc,$(BUILDDIR)/%.o,$(SRCS))

TEST_SRCS = $(wildcard $(TESTDIR)/*.c)
TEST_EXECS = $(patsubst $(TESTDIR)/%.c,$(TESTBUILDDIR)/%,$(TEST_SRCS))

all: $(TARGET) $(TEST_EXECS)
	
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTBUILDDIR)/%: $(TESTDIR)/%.c
	@mkdir -p $(@D)
	$(CC2) $(CFLAGS) -o $@ $<

# build only fuzzer source
.PHONY: fuzz
fuzz: $(TARGET)

# build only test binaries
.PHONY: tests
tests: $(TEST_EXECS)

# Debug build
.PHONY: debug
debug: CFLAGS = -Wall -g
debug: $(TARGET)

# clean up build dir
.PHONY: clean
clean:
	rm -rf $(BUILDDIR) $(TESTBUILDDIR)
	rm -f $(TARGET)
	rm -f input*
	rm -f log
