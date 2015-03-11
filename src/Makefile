CC = gcc
TARGET = ndisc6

CFLAGS = -std=gnu99 -I. -I..

LDFLAGS = -lrt

OBJ = ndisc.o

all: $(TARGET)
$(OBJ) : ndisc.c
	$(CC) -c $(CFLAGS) -o $@ $<
$(TARGET) : $(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -f *.o ndisc6
