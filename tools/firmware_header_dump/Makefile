PROG = fwheader
OBJS = heap_reap.o firmware_header_dump.o
CFLAGS = -std=c11 -g

export PROG

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.c:
	$(CC) $(CFLAGS) -c $@

clean:
	-rm -f $(PROG) $(OBJ)

tests:
	$(MAKE) -C testsuite

.PHONY: clean
