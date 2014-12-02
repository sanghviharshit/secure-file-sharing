CC=g++
TARGETS=main

all: $(TARGETS)

main: main.cpp aes256.c aes256.h
	$(CC) -o main main.cpp aes256.c

clean:
	-rm $(TARGETS)

