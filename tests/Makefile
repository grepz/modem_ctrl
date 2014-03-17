include ../Make.defs

all: ptest

ptest: cmd_parser.c
	$(CC) $(DEFS) $(CFLAGS) $^ -o $@

clean:
	rm -f *.o ptest
