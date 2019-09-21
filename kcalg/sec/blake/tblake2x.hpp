
#ifndef tblake2x_hpp
#define tblake2x_hpp

#include <stdio.h>

#include <stdlib.h>
#include <string>

using namespace std;

namespace ALG {
    int tblake2xs_data_md(const string &data, unsigned char *md, unsigned int outLen);
    int tblake2xb_data_md(const string &data, unsigned char *md, unsigned int outLen);
}

#endif /* tblake2x_hpp */
