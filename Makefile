CC=gcc
CFLAGS=-I. -g
LIBS = -lpthread -lssl
DEPS = ssl.h utils.h
OBJ = ssl.o sslV3MasterSecret.o finished.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

ssl: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f ssl *.o
