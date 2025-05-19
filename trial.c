#include <stdio.h>
#include <string.h>

#define SRC_STR "0123456789abcdef0123456789abcde" // 32 chars including null terminator

typedef struct _charVoid
{
    char charFirst[16];
    void *voidSecond;
    void *voidThird;
} charVoid;

int main()
{
    charVoid structCharVoid;
    structCharVoid.voidSecond = (void *)SRC_STR;

    puts((char *)structCharVoid.voidSecond);

    // Vulnerability: Overwrites memory beyond charFirst, corrupting voidSecond and voidThird
    memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));

    structCharVoid.charFirst[15] = '\0'; // null-terminate

    puts(structCharVoid.charFirst);          // prints truncated string
    puts((char *)structCharVoid.voidSecond); // likely corrupted

    return 0;
}

// EOF 
