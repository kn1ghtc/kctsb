#include <NTL/ZZ.h>
#include <cstdio>
using namespace NTL;
int main() {
    ZZ a;
    a = 1;
    unsigned char buf[32] = {0};
    BytesFromZZ(buf, a, 32);
    printf(\
BytesFromZZ
for
a=1:\n\);
    for(int i = 0; i < 32; i++) printf(\%02x
\, buf[i]);
    printf(\\n\);
    printf(\bytes[0]=%d
bytes[31]=%d\n\, buf[0], buf[31]);
}
