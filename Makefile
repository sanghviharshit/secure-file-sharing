CC=g++
TARGETS=main PreProcess Authorize Recover

all: $(TARGETS)

main: main.cpp aes256.c aes256.h sha256.cpp sha256.h
	$(CC) -o main main.cpp aes256.c sha256.cpp

PreProcess: PreProcess.cpp aes256.c aes256.h sha256.cpp sha256.h
	$(CC) -o PreProcess PreProcess.cpp aes256.c sha256.cpp

Authorize: Authorize.cpp aes256.c aes256.h sha256.cpp sha256.h
	$(CC) -o Authorize Authorize.cpp aes256.c sha256.cpp

Recover: Recover.cpp aes256.c aes256.h sha256.cpp sha256.h
	$(CC) -o Recover Recover.cpp aes256.c sha256.cpp

clean:
	-rm $(TARGETS)

