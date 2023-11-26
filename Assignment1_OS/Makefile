find_roots_lib: find_roots_lib.o libroots.a
	gcc find_roots_lib.o -Wall -g -L. -lroots -o find_roots_lib

find_roots_lib.o: find_roots_lib.c
	gcc -c find_roots_lib.c -o find_roots_lib.o -Wall -g

libroots.a: roots.o
	ar rcs libroots.a roots.o
	ranlib libroots.a

roots.o: roots.c roots.h
	gcc -c roots.c -o roots.o -Wall -g

clean: 
	rm *.o *.a find_roots_lib
