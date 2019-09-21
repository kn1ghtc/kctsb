#ifndef __ALG_BASE64_H_
#define __ALG_BASE64_H_

#include <iostream>
#include <string>

/*
base64 standard dictionary
*/
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool is_base64(unsigned char c);
std::string base64_encode(const unsigned char* bytes_to_encode, unsigned int in_len);
std::string base64_decode(std::string const& encoded_string);
#endif