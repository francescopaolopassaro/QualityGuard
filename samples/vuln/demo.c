#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void run(const char *cmd) {
    char buf[64];
    system(cmd);
    strcpy(buf, cmd);
    gets(buf);
    printf(cmd);
}

int main() {
    return 0;
}