CPPFLAGS=-Wall -W -std=c++11 -DNDEBUG -g2 -I$(HELib)
LIBS=$(HELib)/fhe.a -lntl -lgmp -lm
TARGET=simpleFHETimeCalc

.PHONY: all clean

all: $(TARGET)

$(TARGET): main.cpp
	g++ $(CPPFLAGS) $< -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
