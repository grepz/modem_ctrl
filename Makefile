PRODUCT = modem_ctrl

CC = gcc
LD = ld

DEFS = -DDEBUG

# -rdynamic
CFLAGS = -O0 -g -fno-stack-protector
CFLAGS += -Wall -Wextra -Warray-bounds -pthread

SRCS = main.c modem.c bson/bson.c bson/encoding.c bson/numbers.c

all: $(PRODUCT)

$(PRODUCT): $(SRCS)
	$(CC) $(DEFS) $(CFLAGS) $^ -o $@

clean:
	rm -f *.o $(PRODUCT)
