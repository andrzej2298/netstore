CXX=g++
CPPFLAGS=-std=c++14 -Wall -Wextra -g -lboost_program_options

all: netstore-client netstore-server

netstore-client: client.cpp
	$(CXX) $(CPPFLAGS) $< -o $@

netstore-server: server.cpp
	$(CXX) $(CPPFLAGS) $< -o $@

clean:
	rm -f netstore-client netstore-server *.o *~ *.bak
