CC=g++
BIN := bin
TARGETS=$(BIN)/main $(BIN)/PreProcess $(BIN)/Authorize $(BIN)/Recover
SRCDIR := src
EXTDIR := ext

all: $(TARGETS)

$(BIN)/main:
	$(CC) -I include -o $(BIN)/main $(SRCDIR)/main.cpp $(EXTDIR)/aes256.cpp $(EXTDIR)/sha256.cpp

$(BIN)/PreProcess:
	$(CC) -I include -o $(BIN)/PreProcess $(SRCDIR)/PreProcess.cpp $(EXTDIR)/aes256.cpp $(EXTDIR)/sha256.cpp

$(BIN)/Authorize:
	$(CC) -I include -o $(BIN)/Authorize $(SRCDIR)/Authorize.cpp $(EXTDIR)/aes256.cpp $(EXTDIR)/sha256.cpp

$(BIN)/Recover:
	$(CC) -I include -o $(BIN)/Recover $(SRCDIR)/Recover.cpp $(EXTDIR)/aes256.cpp $(EXTDIR)/sha256.cpp

clean:
	-rm $(TARGETS)

