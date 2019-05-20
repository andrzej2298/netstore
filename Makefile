CXX=g++
CPPFLAGS=-std=c++17 -Wall -Wextra -g -lboost_program_options -lboost_system -lboost_filesystem

all: netstore-client netstore-server

netstore-client: client.cpp connection.h
	$(CXX) $(CPPFLAGS) $< -o $@

netstore-server: server.cpp connection.h
	$(CXX) $(CPPFLAGS) $< -o $@

clean:
	rm -f netstore-client netstore-server *.o *~ *.bak
