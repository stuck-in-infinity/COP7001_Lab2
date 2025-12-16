CXX = g++
CC  = gcc

CXXFLAGS = -std=c++17 -Wall -Wextra -g
CFLAGS   = -g -no-pie

SRC_CPP = debugger.cpp
BIN_CPP = dbg

SRC_C   = test.c
BIN_C   = test

all: $(BIN_CPP) $(BIN_C)

$(BIN_CPP): $(SRC_CPP)
	$(CXX) $(CXXFLAGS) -o $(BIN_CPP) $(SRC_CPP)

$(BIN_C): $(SRC_C)
	$(CC) $(CFLAGS) -o $(BIN_C) $(SRC_C)

clean:
	rm -rf $(BIN_CPP) $(BIN_C)

.PHONY: all clean
