#ifndef __TSB_COMMON_H_
#define __TSB_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <stdint.h>
#include <map>
#include <vector>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include <objbase.h>
#include <io.h>
#include <direct.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#elif defined(ANDROID)
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <string.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define MAX_NAME 32
#define MAX_TIPS 128
#define MAX_DATA 2048
#define NODE_OFFSET 8
#define MAX_HEADER_DATA 1024
#define MAX_VERSION 8
#define MAX_UUID_LEN 64
#define MAX_SHA256_LEN 32
#define MAX_SHA512_LEN 64
#define MAX_AESPARAM_LEN 16
#define MAX_HEADER_CRC 32
#define MAX_RK_LEN    16
#define MAX_DES_LEN  64
#define MAX_MAC_DATA 64
#define MAX_UID_LENGTH 128

#define MAX_RAND_LEN 32
#define MAX_SKBRAND_LEN 256
#define MIN_LOGIN_KEY 6
#define MAX_ECC_DATALEN 30*1024

#define DEFAULT_MAC "mac"
#define DEFAULT_IMEI "imei"
#define DEFAULT_DEVICETYPE "others"
#define DEFAULT_FILE_NAME "cdtp.cfs"
#define DEFAULT_GENERATE_TSB "---uid--publictsbuid--uid---"
#define VERSION_LOWEST "1.0.1"

enum nodeState
{
	Free = 0,
	Active
};

enum nodeType
{
	Folder = 0,
	File
};

enum safeLevel
{
	stand = 0,
	enableRK
};

#if defined(ANDROID)
#define _to_string to_stringAndroid
#define _stoi stoi_Android
static std::string to_stringAndroid(int32_t value)
{
	char temp[32]={0};
	sprintf(temp,"%d",value);
	return temp;
}

static int32_t stoi_Android(std::string value)
{
	return atoi(value.c_str());
}
#else
#define _to_string std::to_string
#define _stoi  std::stoi
#endif


#pragma pack(push,8)
typedef struct _tsfs_node
{
	char swapBits;                //switch length, the random number 1-7, eg, it's 5 , for data, the 5 Byte with 3 Byte switch
	int64_t id;                   //node Id, it's current time ,microsecond .
	int64_t parentId;             //parent node Id
	int64_t leftId;               //left node Id
	int64_t rightId;              //right node Id
	int32_t   type;               //0 -folder 1 -file.
	int32_t   state;              //0 -delete ,1-active
	int32_t   nameLength;
	unsigned char  name[MAX_NAME];         //node name
	int32_t  signedDataLength;
	unsigned char  signedData[MAX_DATA];   //all node data to sign
	int32_t  dataLength;
	unsigned char  data[MAX_DATA];         //data   should be : >MAX_KEY_DATA + MAX_KEY_MAC + MAX_KEY_BODY+2
	int32_t  macDataLength;
	unsigned char  macData[MAX_MAC_DATA];   //
	int32_t  dataEncryMethod;
}_tsfsNode;

typedef struct _tsfs_header
{
	char swapBits;         //1 byte swap bit, it's 1-7 random number .
	char uuid[MAX_UUID_LEN];
	char version[MAX_VERSION];
	unsigned char fingerData[MAX_HEADER_DATA];
	unsigned char signedData[MAX_HEADER_DATA];
	int32_t rootOffset;
}_tsfsHeader;

typedef struct _tsfs_pc_header
{
	char uid[MAX_UUID_LEN];
	int32_t slevel;
	int64_t createtime;
	char tips[MAX_TIPS];
	char version[MAX_VERSION];
	char description[MAX_DES_LEN];
	char rand[MAX_RAND_LEN];
	char skbrand[MAX_SKBRAND_LEN];
	char CRC[MAX_HEADER_CRC];
}_tsfspcheader;
#pragma pack(pop)

typedef std::vector<_tsfsNode>::iterator tsfsTree_it;
typedef enum{QI_MALLOC, QI_NEW} QIPTRMALLOCTYPE;

template <typename T>
shared_ptr<T> tsb_make_shared_array(size_t size)
{
	return shared_ptr<T>(new T[size], default_delete<T[]>());
}
#endif
