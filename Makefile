PRODUCT = modem_ctrl

SRCS = main.c modem.c utils.c bson/bson.c bson/encoding.c bson/numbers.c

-include Make.defs

TESTS_DIR = tests

.PHONY: all clean tests clean_tests

all: $(PRODUCT)

$(PRODUCT): $(SRCS)
	$(CC) $(DEFS) $(CFLAGS) $^ -o $@

tests:
	$(MAKE) -C $(TESTS_DIR)

clean_tests:
	$(MAKE) -C $(TESTS_DIR) clean

clean:
	rm -f *.o $(PRODUCT)
