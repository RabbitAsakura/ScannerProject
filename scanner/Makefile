#Jakobe McPhail, Gerrick Jones, James Riley, Aidan Brown

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread

SRC = src/engine/main.cpp
OBJ = $(SRC:src/%.cpp=obj/%.o)
EXEC = bin/scanner

all: $(EXEC) test_server build_db

$(EXEC): $(OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^ -lsqlite3

obj/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

test_server: src/engine/test_server.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $< -o bin/test_server

build_db: src/nvd/build_db.cpp
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $< -o bin/build_db -lsqlite3

clean:
	rm -rf obj bin nvd_cache.db