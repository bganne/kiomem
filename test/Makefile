CFLAGS:=-O2 -g -Wall -Werror -std=gnu99
LDFLAGS:=-g

all: main

main: main.c

clean:
	$(RM) main

test: main
	sudo ./setup.sh
	./main

.PHONY: all clean test
