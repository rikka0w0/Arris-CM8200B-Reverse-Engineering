PROG = fwex
OBJS = firmware_extractor.o lzw_decode.o heap_reap.o
CFLAGS = -Wall -std=c11 -g -DPROGRAM_NAME=\"$(PROG)\" -DCOMPRESSED_CONFIG_FILE

export PROG

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.c:
	$(CC) $(CFLAGS) -c $@

clean:
	-rm -f $(PROG) $(OBJS)

tests:
	$(MAKE) -C testsuite

.PHONY: clean
