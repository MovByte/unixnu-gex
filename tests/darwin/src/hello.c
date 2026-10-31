// The first program through Apple's dyld: libSystem from the shared cache.

#include <stdio.h>

int main(int argc, char **argv) {
    printf("hello from %s with %d argument%s\n", argv[0], argc - 1, argc == 2 ? "" : "s");
    return 0;
}
