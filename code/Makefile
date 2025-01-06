# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -I/opt/homebrew/include -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/lib -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lmpg123 -lportaudio

# Targets
CLIENT_TARGET = client
SERVER_TARGET = server

# Source files
CLIENT_SRC = client.cpp
SERVER_SRC = server.cpp

# Default target: Build both client and server
all: $(CLIENT_TARGET) $(SERVER_TARGET)

# Build client executable
$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) $(CLIENT_SRC) -o $(CLIENT_TARGET) $(LDFLAGS)

# Build server executable
$(SERVER_TARGET): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) $(SERVER_SRC) -o $(SERVER_TARGET) $(LDFLAGS)

# Clean up all build artifacts
clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET)
	@echo "Cleaned up all build artifacts."

# Display help
help:
	@echo "Makefile targets:"
	@echo "  all             - Build both client and server."
	@echo "  $(CLIENT_TARGET) - Build the client executable."
	@echo "  $(SERVER_TARGET) - Build the server executable."
	@echo "  clean           - Remove all build artifacts."
