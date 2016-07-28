CC = gcc
CFLAGS=-Wall -O0 -g
EXE=$(patsubst %.c,%,$(wildcard *.c))
.PHONY: all clean
all: $(EXE)
%: %.c
	@-mkdir build
	@$(CC) $< -o ./build/$@ $(CFLAGS) $(CPPFLAGS)
clean:
	@rm ./build/$(EXE)
