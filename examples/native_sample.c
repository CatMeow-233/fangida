#include <stdio.h>

static int add_one(int value) {
    return value + 1;
}

int main(void) {
    int result = add_one(41);
    printf("result=%d\n", result);
    return result == 42 ? 0 : 1;
}
