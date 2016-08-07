CC = gcc
CFLAGS=-Wall -O0 -g --shared -fPIC
EXE=$(patsubst %.c,%.so,$(wildcard *.c))
.PHONY: all clean
all: $(EXE)
%.so: %.c
	@$(CC) $< -o ../build/$@ $(CFLAGS) $(CPPFLAGS)
clean:
	@rm ../build/$(EXE)
