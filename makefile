BOFNAME := entra-authcode-flow
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CFLAGS := -Iinclude

all:
	$(CC_x64) -o dist/$(BOFNAME).x64.o -c src/$(BOFNAME).c $(CFLAGS)
	$(CC_x86) -o dist/$(BOFNAME).x86.o -c src/$(BOFNAME).c $(CFLAGS)
