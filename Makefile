CC=g++
TARGETS=main

all: $(TARGETS)

main: main.cpp aes256.c aes256.h sha256.cpp sha256.h
	$(CC) -o main main.cpp aes256.c sha256.cpp

clean:
	-rm $(TARGETS)

