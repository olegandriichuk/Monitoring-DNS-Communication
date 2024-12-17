CC = g++
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap
RM = rm -f

# Target executable and object files
TARGET = dns-monitor
OBJECTS = main.o filesOperations.o helpFunctions.o parseFunctions.o printFunctions.o processPacket.o

# Default target, builds the executable
.PHONY: all clean

all: $(TARGET)

# Linking step: creates the final executable
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

# Compiling main.o
main.o: main.cpp filesOperations.h helpFunctions.h parseFunctions.h printFunctions.h processPacket.h
	$(CC) $(CFLAGS) -c main.cpp

# Compiling filesOperations.o
filesOperations.o: filesOperations.cpp filesOperations.h
	$(CC) $(CFLAGS) -c filesOperations.cpp

# Compiling helpFunctions.o
helpFunctions.o: helpFunctions.cpp helpFunctions.h
	$(CC) $(CFLAGS) -c helpFunctions.cpp

# Compiling parseFunctions.o
parseFunctions.o: parseFunctions.cpp parseFunctions.h
	$(CC) $(CFLAGS) -c parseFunctions.cpp

# Compiling printFunctions.o
printFunctions.o: printFunctions.cpp printFunctions.h
	$(CC) $(CFLAGS) -c printFunctions.cpp

# Compiling processPacket.o
processPacket.o: processPacket.cpp processPacket.h
	$(CC) $(CFLAGS) -c processPacket.cpp

# Clean up build artifacts
clean:
	$(RM) *.o $(TARGET) *.out
