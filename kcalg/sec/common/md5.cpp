
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <openssl/md5.h>
#include <memory>
#include "algApi.h"
#include "tsbCommon.h"

namespace ALG
{
	int64_t md5_encrypt_file(char *path, int32_t md5_len, BufferArray &output)
	{
		MD5_CTX mdContext;
		int32_t bytes;
		unsigned char data[1024] = { 0 };
		unsigned char buffer[MD5_DIGEST_LENGTH] = { 0 };
		auto result = tsb_make_shared_array<char>(md5_len+1);
		if (result.get() == NULL)
		{
			fprintf(stderr, "malloc memory failed\n");
			return ERR_MEMORY_FAILED;
		}
		memset(result.get(), 0, (md5_len + 1));

		FILE *fp = fopen(path, "rb");
		if (fp == NULL) {
			fprintf(stderr, "fopen %s failed\n", path);
			return ERR_CFSFILE_INVALID;
		}
		MD5_Init(&mdContext);
		while ((bytes = fread(data, 1, 1024, fp)) != 0)
		{
			MD5_Update(&mdContext, data, bytes);
		}
		MD5_Final(buffer, &mdContext);

		if (md5_len == 16)
		{
			for (int32_t i = 4; i < 12; i++)
			{
				sprintf(&result.get()[(i - 4) * 2], "%02x", buffer[i]);
			}
		}
		else if (md5_len == 32)
		{
			for (int32_t i = 0; i < 16; i++)
			{
				sprintf(&result.get()[i * 2], "%02x", buffer[i]);
			}
		}
		else
		{
			fclose(fp);
			return ERR_MD5HASH_FAILED;
		}
		fclose(fp);

		result.get()[md5_len] = '\0';
		output.assign(result.get(), result.get()+ md5_len);
		return ERR_SUCCESS;
	}
	int64_t md5_encrypt_str(unsigned char *str, int32_t len, int32_t md5_len, BufferArray &output)
	{
		if (!str || len == 0)
		{
			fprintf(stderr, "param invalid \n");
			return ERR_PARAM_INVALID;
		}
		unsigned char buffer[MD5_DIGEST_LENGTH] = { 0 };
		auto result = tsb_make_shared_array<char>(md5_len+1);
		if (result.get() == NULL)
		{
			fprintf(stderr, "malloc memory failed\n");
			return ERR_MEMORY_FAILED;
		}
		memset(result.get(), 0, (md5_len + 1));

		MD5(str, len, buffer);
		if (md5_len == 16)
		{
			for (int32_t i = 4; i < 12; i++)
			{
				sprintf(&result.get()[(i - 4) * 2], "%02x", buffer[i]);
			}
		}
		else if (md5_len == 32)
		{
			for (int32_t i = 0; i < 16; i++)
			{
				sprintf(&result.get()[i * 2], "%02x", buffer[i]);
			}
		}
		else
			return ERR_MD5HASH_FAILED;

		result.get()[md5_len] = '\0';
		output.assign(result.get(), result.get() + md5_len);
		return ERR_SUCCESS;
	}
};
