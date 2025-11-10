CROSS_COMPILE ?= x86_64-linux-gnu-
CFLAGS ?= -Wall -Werror

CC = $(CROSS_COMPILE)gcc
TARGET = aesdsocket
OBJS = aesdsocket.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean