CC=gcc
CFLAGS=-I include -g -rdynamic
DEPS=app.h util.h web.h cast.h cast_channel.pb.h
OBJ=main.o web.o cast.o cast_channel.o tiny-json.o

app: $(OBJ) $(DEPS)
	gcc -o app $(OBJ) $(CFLAGS) -lssl -lcrypto
	ctags -R .

main.o: main.c $(DEPS)
web.o: web.c $(DEPS)
cast.o: cast.c cast_channel.o tiny-json.o $(DEPS)
tiny-json.o: tiny-json.c

cast_channel.o: cast_channel.proto
	python nanopb/generator/nanopb_generator.py cast_channel.proto
	gcc -c cast_channel.pb.c -o cast_channel.o -I include

.PHONY: clean
clean:
	rm *.o
