CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g
SRC = src/debugger_part4.cpp
BIN = dbg_part4

all: $(BIN)

$(BIN): $(SRC)
	mkdir -p bin
	$(CXX) $(CXXFLAGS) -o bin/$(BIN) $(SRC)

clean:
	rm -rf bin

.PHONY: all clean
