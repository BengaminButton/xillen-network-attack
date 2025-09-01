CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
TARGET = xillen_network_attack
SOURCE = network_attack.cpp

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    CXXFLAGS += -D_LINUX
    LIBS = -lpthread
else ifeq ($(UNAME_S),Darwin)
    CXXFLAGS += -D_MACOS
    LIBS = -lpthread
else ifeq ($(UNAME_S),MINGW32_NT-6.1)
    CXXFLAGS += -D_WIN32
    LIBS = -lws2_32 -liphlpapi
else ifeq ($(UNAME_S),MINGW64_NT-6.1)
    CXXFLAGS += -D_WIN32
    LIBS = -lws2_32 -liphlpapi
else ifeq ($(UNAME_S),CYGWIN_NT-6.1)
    CXXFLAGS += -D_WIN32
    LIBS = -lws2_32 -liphlpapi
endif

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)
	@echo "Build completed successfully!"
	@echo "Executable: $(TARGET)"

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build
release: CXXFLAGS += -DNDEBUG -O3
release: $(TARGET)

# Clean build files
clean:
	rm -f $(TARGET) *.o *.exe
	@echo "Clean completed!"

# Install (copy to /usr/local/bin on Unix-like systems)
install: $(TARGET)
	@if [ "$(UNAME_S)" = "Linux" ] || [ "$(UNAME_S)" = "Darwin" ]; then \
		sudo cp $(TARGET) /usr/local/bin/; \
		sudo chmod +x /usr/local/bin/$(TARGET); \
		echo "Installed to /usr/local/bin/$(TARGET)"; \
	else \
		echo "Install target not supported on this platform"; \
	fi

# Uninstall
uninstall:
	@if [ "$(UNAME_S)" = "Linux" ] || [ "$(UNAME_S)" = "Darwin" ]; then \
		sudo rm -f /usr/local/bin/$(TARGET); \
		echo "Uninstalled from /usr/local/bin/$(TARGET)"; \
	else \
		echo "Uninstall target not supported on this platform"; \
	fi

# Run with default parameters
run: $(TARGET)
	@echo "Running $(TARGET) with default parameters..."
	@echo "Usage: ./$(TARGET) <target_ip> <target_port> [options]"
	@echo "Example: ./$(TARGET) 192.168.1.100 80 --verbose"

# Test build
test: $(TARGET)
	@echo "Testing build..."
	@if [ -f "$(TARGET)" ]; then \
		echo "Build test passed!"; \
	else \
		echo "Build test failed!"; \
		exit 1; \
	fi

# Show help
help:
	@echo "XILLEN Network Attack Tool - Makefile"
	@echo "====================================="
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build the executable (default)"
	@echo "  debug      - Build with debug symbols"
	@echo "  release    - Build optimized release version"
	@echo "  clean      - Remove build files"
	@echo "  install    - Install to system (Unix-like only)"
	@echo "  uninstall  - Remove from system (Unix-like only)"
	@echo "  run        - Run with default parameters"
	@echo "  test       - Test if build was successful"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Build variables:"
	@echo "  CXX        - C++ compiler (default: g++)"
	@echo "  CXXFLAGS   - Compiler flags"
	@echo "  LIBS       - Linker libraries"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build release version"
	@echo "  make debug              # Build debug version"
	@echo "  make CXX=clang++       # Use different compiler"
	@echo "  make clean && make     # Clean rebuild"

# Phony targets
.PHONY: all debug release clean install uninstall run test help

# Show compiler info
info:
	@echo "Compiler: $(CXX)"
	@echo "Flags: $(CXXFLAGS)"
	@echo "Libraries: $(LIBS)"
	@echo "Platform: $(UNAME_S)"
	@echo "Target: $(TARGET)"
	@echo "Source: $(SOURCE)"

# Dependencies check
deps:
	@echo "Checking dependencies..."
	@which $(CXX) > /dev/null || (echo "Error: $(CXX) not found" && exit 1)
	@echo "✓ $(CXX) found"
	@echo "✓ Dependencies check passed"

# Format code (requires clang-format)
format:
	@if command -v clang-format > /dev/null; then \
		clang-format -i $(SOURCE); \
		echo "Code formatted with clang-format"; \
	else \
		echo "clang-format not found. Install it to format code."; \
	fi

# Static analysis (requires cppcheck)
analyze:
	@if command -v cppcheck > /dev/null; then \
		cppcheck --enable=all --std=c++17 $(SOURCE); \
		echo "Static analysis completed"; \
	else \
		echo "cppcheck not found. Install it for static analysis."; \
	fi
