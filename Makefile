CC      = gcc
TARGET  = ezdbg
SRCS    = breakpoint.c commands.c display.c dwarf.c ezdbg.c \
          repl.c run_debugger.c run_program.c util.c
OBJS    = $(SRCS:.c=.o)

CFLAGS  = -Wall -Wextra -pedantic -std=c11
LIBS    = -ldwarf -lelf

# Build modes: make (release) or make debug
DEBUG_FLAGS   = -g -O0 -DDEBUG
RELEASE_FLAGS = -O2

# Default to release
CFLAGS += $(RELEASE_FLAGS)

.PHONY: all debug clean install uninstall

all: $(TARGET)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: CFLAGS := $(filter-out $(RELEASE_FLAGS),$(CFLAGS))
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)
	@echo "Build successful -> ./$(TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install to /usr/local/bin
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	@echo "Installed to /usr/local/bin/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled $(TARGET)"

clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Cleaned build artifacts"