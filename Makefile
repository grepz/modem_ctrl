PRODUCT = modem_ctrl

CC = gcc
LD = ld

DEFS = -DDEBUG

CFLAGS = -O0
CFLAGS += -Wall -Wextra -Warray-bounds -pthread

SRCS = main.c modem.c

all: $(PRODUCT)

$(PRODUCT): $(SRCS)
	$(CC) $(DEFS) $(CFLAGS) $^ -o $@

clean:
	rm -f *.o $(PRODUCT)
