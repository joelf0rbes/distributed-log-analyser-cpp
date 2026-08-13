# Makefile for Client-Server Log Analysis App

CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread
CLIENT_SRC = ../client/client.cpp
SERVER_SRC = ../server/server.cpp
CLIENT_BIN = client
SERVER_BIN = server
CLIENT_LIBS = -ltinyxml2

.PHONY: all client server run_client run_server clean

all: client server

client: $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $(CLIENT_BIN) $(CLIENT_SRC) $(CLIENT_LIBS)

server: $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $(SERVER_BIN) $(SERVER_SRC)

run_client: client
	./$(CLIENT_BIN)

run_server: server
	./$(SERVER_BIN)

clean:
	rm -f $(CLIENT_BIN) $(SERVER_BIN) summary.txt