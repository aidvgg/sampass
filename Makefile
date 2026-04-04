UNAME_S := $(shell uname -s)
CC      ?= cc
CFLAGS  = -Wall -Wextra -Wno-unused-parameter -O2 -I./include

ifeq ($(UNAME_S),Darwin)
  # macOS with Homebrew
  CFLAGS  += -I/opt/homebrew/opt/openssl@3.6/include \
             -I/opt/homebrew/include
  LDFLAGS  = -L/opt/homebrew/opt/openssl@3.6/lib -lssl -lcrypto \
             -L/opt/homebrew/lib -lusb-1.0
else
  # Linux — use pkg-config if available, fallback to standard paths
  LIBUSB_CFLAGS := $(shell pkg-config --cflags libusb-1.0 2>/dev/null)
  LIBUSB_LIBS   := $(shell pkg-config --libs libusb-1.0 2>/dev/null || echo "-lusb-1.0")
  SSL_CFLAGS    := $(shell pkg-config --cflags openssl 2>/dev/null)
  SSL_LIBS      := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")
  CFLAGS  += $(LIBUSB_CFLAGS) $(SSL_CFLAGS)
  LDFLAGS  = $(LIBUSB_LIBS) $(SSL_LIBS)
endif

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
