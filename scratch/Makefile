CROSS_COMPILE ?= x86_64-linux-gnu-
CFLAGS ?= -Wall -Werror

CC = $(CROSS_COMPILE)gcc
TARGETS = parent child

.PHONY: all clean

all: $(TARGETS)

parent: parent.o
	$(CC) $(CFLAGS) -o $@ $^

child: child.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(TARGETS) *.o
