CC = gcc
CFLAGS=-Wall -O0 -g
OBJS=$(patsubst %.c,%.o,$(wildcard *.c))
EXE=../build/prime
.PHONY: all clean
all: $(OBJS)
	$(CC) -o $(EXE) $(OBJS)
%.o: %.c
	@$(CC) $< -c $(CFLAGS) $(CPPFLAGS)
clean:
	@-rm $(EXE)
	@-rm $(OBJS)
