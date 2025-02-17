CC = g++
CFLAGS = -Wall

SRCDIR = src
BUILDDIR = obj

TESTDIR = tests
TESTBUILDDIR = tests_bin

TARGET = $(BUILDDIR)/a.out

SRCS = $(wildcard $(SRCDIR)/*.cc)
OBJS = $(patsubst $(SRCDIR)/%.cc,$(BUILDDIR)/%.o,$(SRCS))

TEST_SRCS = $(wildcard $(TESTDIR)/*.cc)
TEST_EXECS = $(patsubst $(TESTDIR)/%.cc,$(TESTBUILDDIR)/%,$(TEST_SRCS))

all: $(TARGET) $(TEST_EXECS)
	
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(TESTBUILDDIR)/%: $(TESTDIR)/%.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<


# clean up build dir
.PHONY: clean
clean:
	rm -rf $(BUILDDIR) $(TESTBUILDDIR)
