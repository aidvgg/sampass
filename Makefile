CC      = clang
CFLAGS  = -Wall -Wextra -Wno-unused-parameter -O2 -I./include \
          -I/opt/homebrew/opt/openssl@3.6/include \
          -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3.6/lib -lssl -lcrypto \
          -L/opt/homebrew/lib -lusb-1.0

SRCDIR  = src
SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(SRCS:.c=.o)
TARGET  = sampass

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c include/sampass.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o $(TARGET)
