#Jakobe McPhail, Gerrick Jones, James Riley, Aidan Brown

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread

SRC = src/engine/main.cpp
OBJ = $(SRC:src/%.cpp=obj/%.o)
EXEC = bin/scanner

all: $(EXEC)

$(EXEC): $(OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^

obj/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf obj bin