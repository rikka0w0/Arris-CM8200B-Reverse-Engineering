PROG=cfe_gen_pass
SRC=cfe_generate_password
CFLAGS=-std=c11

$(PROG): $(SRC).c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROG)

phony: clean
