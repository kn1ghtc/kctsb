#ifndef __TSB_UTILITY_H_
#define __TSB_UTILITY_H_

#include "tsbApi.h"
#include "algApi.h"
#include "tsbCommon.h"
#include <assert.h>
#include <fstream>

#ifdef WIN32
#include <windows.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "User32.lib")
#endif


using namespace tsb;
class utility
{
public:
	static bool existFolder(const char *path)
	{
		assert(path);
		int32_t res = -1;
#ifdef _WIN32
		res = _access(path, 06);
#else
		res = access(path, 06);
#endif
		if (res != -1){
			return true;
		}
		return createDir(path);
	}
	static bool existFile(std::string path)
	{
		assert(!path.empty());
#ifdef _WIN32
		return _access(path.c_str(), 00) != -1;
#else
		return access(path.c_str(), 00) != -1;
#endif
	}
#ifdef _WIN32
	static std::wstring utf8ToUnicode(const char* utf8)
	{
		if (!utf8 || !strlen(utf8))
		{
			return L"";
		}
		int dwUnicodeLen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
		size_t num = dwUnicodeLen * sizeof(wchar_t);
		wchar_t *pwText = new wchar_t[num];
		memset(pwText, 0, num);
		MultiByteToWideChar(CP_UTF8, 0, utf8, -1, pwText, dwUnicodeLen);
		std::wstring unicode = pwText;
		delete pwText;
		return unicode;
	}

	static std::string unicodeToUtf8(const wchar_t* unicode)
	{
		int len;
		len = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)unicode, -1, NULL, 0, NULL, NULL);
		char *szUtf8 = new char[len + 1];
		memset(szUtf8, 0, len + 1);
		len = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)unicode, -1, szUtf8, len, NULL, NULL);
		std::string utf8 = szUtf8;
		delete szUtf8;
		return utf8;
	}
	static string changeDirectoryFormat(std::string &path)
	{
		while (true) {
			string::size_type pos(0);
			if ((pos = path.find("/")) != string::npos)
				path.replace(pos, 1, "\\");
			else
				break;
		}

		string::size_type pos(0);
		if ((pos = path.find("\\\\")) != string::npos)
			path.replace(pos, 2, "\\");

		return path;
	}

	static void createDirectories(std::wstring wszDirectory)
	{
		BOOL    bRetCode = TRUE;

		PWCHAR  pwszDirectory = NULL;
		pwszDirectory = (PWSTR)wszDirectory.c_str();
		LPWSTR  lpwSubDirectoryPos = NULL;
		WCHAR   wszSubDirectory[MAX_PATH] = { 0 };

		lpwSubDirectoryPos = pwszDirectory;
		while (lpwSubDirectoryPos = wcschr(lpwSubDirectoryPos, '\\')) {
			memset(wszSubDirectory, 0, sizeof(wszSubDirectory));
			wcsncpy_s(wszSubDirectory, pwszDirectory, lpwSubDirectoryPos - pwszDirectory);

			if (::PathFileExists(wszSubDirectory) == FALSE) {
				bRetCode = ::CreateDirectory(wszSubDirectory, NULL);
				if (FALSE == bRetCode) {
					break;
				}
			}
			else {
				bRetCode = ::PathIsDirectory(wszSubDirectory);
				if (FALSE == bRetCode) {
					break;
				}
			}

			lpwSubDirectoryPos++;
		}

		if (bRetCode != FALSE) {
			if (::PathFileExists(pwszDirectory) == FALSE) {
				bRetCode = ::CreateDirectory(pwszDirectory, NULL);
			}
		}
	}
	static bool tsbMkdir(const char *pszDir)
	{
		bool res = false;
		char str[512] = {0};
		strncpy(str, pszDir, 512);
		int32_t len = strlen(str);
		for (int32_t i = 0; i < len; i++)
		{
			if (str[i] == '\\' || str[i] == '/')
			{
				str[i] = '\0';
#ifdef _WIN32
				if (_access(str, 0) != 0)
				{
					res = _mkdir(str) == 0;
				}
#else
				if (access(str, 0) != 0)
				{
					res = mkdir(str, 0777) == 0;
				}
#endif
				str[i] = '/';
			}
		}
#ifdef _WIN32
		if (len > 0 && _access(str, 0) != 0)
		{
			res = _mkdir(str) == 0;
		}
#else
		if (len > 0 && access(str, 0) != 0)
		{
			res = mkdir(str, 0777) == 0;
		}
#endif
		return res;
	}
#endif
	static bool createDir(const char *dir)
	{
        bool ret = true;
#ifndef _WIN32
		if ( 0 != ::mkdir(dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) )
        {
            ret = false;
        }
#else
		tsbMkdir(dir);
#endif
		return ret;
	}
	static void replace(std::string &strBase, std::string strSrc, std::string strDes)
	{
		std::string::size_type pos = 0;
		std::string::size_type srcLen = strSrc.size();
		std::string::size_type desLen = strDes.size();
		pos = strBase.find(strSrc, pos);
		while ((pos != std::string::npos))
		{
			strBase.replace(pos, srcLen, strDes);
			pos = strBase.find(strSrc, (pos + desLen));
		}
	}
	static std::string base64_safe_encode(std::string oriBase)
	{
		utility::replace(oriBase, "+", "-");
		utility::replace(oriBase, "/", "_");
		utility::replace(oriBase, "=", "");
		return oriBase;
	}
	static std::string base64_safe_decode(std::string oriBase)
	{
		utility::replace(oriBase, "-", "+");
		utility::replace(oriBase, "_", "/");
		int32_t mode = oriBase.length() % 4;
		if (mode > 0)
		{
			oriBase += std::string("====").substr(0, 4 - mode);
		}
		return oriBase;
	}
	std::vector<int32_t> split(std::string str, char a)
	{
		vector<int32_t> strvec;
		std::string::size_type pos1 = 0, pos2;
		pos2 = str.find(a);
		while (string::npos != pos2)
		{
			strvec.push_back(atoi(str.substr(pos1, pos2 - pos1).c_str()));
			pos1 = pos2 + 1;
			pos2 = str.find(a, pos1);
		}
		strvec.push_back(atoi(str.substr(pos1).c_str()));
		return strvec;
	}
	static bool compareVersion(std::string oldV, std::string newV)
	{
		return false;
	}
	static std::string getCfsFilePath(string name, string folder)
	{
		assert(!name.empty());
		assert(!folder.empty());

		utility::replace(folder, "\\", "/");

		std::string fileName = name;
		fileName += ".cfs";
		fileName = "/" + fileName;
		return (folder + fileName);
	}
	static bool copyFile(const char *src, const char *des)
	{
		if (src == NULL || des == NULL)
		{
			std::cout << "copyFile src or des invalid" << endl;
			return false;
		}
		std::ifstream  input(src, ios::binary);
		if (!input)
		{
			std::cout << "copyFile read src failed"<<endl;
			return false;
		}
		std::ofstream  output(des, ios::binary);
		if (!output)
		{
			input.close();
			std::cout << "copyFile read des failed" << endl;
			return false;
		}
		output << input.rdbuf();
		input.close();
		output.close();

		//check
		BufferArray srcMd5, desMd5;
		if (ALG::md5_encrypt_file((char *)src, 32, srcMd5)!= ERR_SUCCESS)
		{
			std::cout << "copyFile get src md5 failed" << endl;
			return false;
		}
		if (ALG::md5_encrypt_file((char *)des, 32, desMd5) != ERR_SUCCESS)
		{
			std::cout << "copyFile get des md5 failed" << endl;
			return false;
		}

		return srcMd5 == desMd5;
	}
	static std::string tolower(const std::string& str) 
	{
		std::string s = str;
		int32_t len = s.size();
		for (int32_t i = 0; i < len; i++)
		{
			if (s[i] >= 'A'&&s[i] <= 'Z') 
			{
				s[i] += 32;
			}
		}
		return s;
	}
	static std::string toupper(const std::string& str) 
	{
		std::string s = str;
		int32_t len = s.size();
		for (int32_t i = 0; i < len; i++)
		{
			if (s[i] >= 'a'&&s[i] <= 'z') 
			{
				s[i] -= 32;
			}
		}
		return s;
	}
	/*
	temporary remove the code, if enble it ,need to include json cpp
	*/
	//static std::string stringTJson(std::map<std::string,std::string> map)
	//{
	//	Json::Value root;
	//	std::map<std::string, std::string>::iterator it;
	//	for (it = map.begin();it != map.end();it++)
	//	{
	//		root[it->first] = it->second;
	//	}
	//	root.toStyledString();
	//	return root.toStyledString();
	//}
	static unsigned char* Char2Hex(unsigned char ch) 
	{
		unsigned char byte[2], i;
		static unsigned char szHex[2];
		byte[0] = ch / 16;
		byte[1] = ch % 16;
		for (i = 0; i < 2; i++) 
		{
			if (byte[i] >= 0 && byte[i] <= 9)
				szHex[i] = '0' + byte[i];
			else
				szHex[i] = 'a' + byte[i] - 10;
		}
		return &szHex[0];
	}

	static BufferArray charToBufferArray(const char * src, long srcLen)
	{
		BufferArray des;
		if (src == NULL || srcLen == 0)
		{
			return des;
		}
		des.assign(src, src + srcLen);
		return des;
	}
	static std::string int64toString(int64_t value)
	{
		char temp[64] = { 0 };
		sprintf(temp, "%lld", value);
		return temp;
	}
	static bool uidTtid(const std::string uid, std::string &tid)
	{
		if (uid.length() == 0)
			return false;
		BufferArray tidArray;
		if (ALG::md5_encrypt_str((unsigned char *)uid.c_str(), \
			uid.length(), 32, tidArray) != ERR_SUCCESS)
		{
			return false;
		}
		tid.assign(tidArray.begin(), tidArray.end());
		return true;
	}
	static bool isValidCFS(const std::string &path)
	{
		if (path.length() == 0)
			return false;
		std::string suffix = ".cfs";
		return path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0 ? true : false;
	}
	static void copyTreeNode(const _tsfsNode srcNode, _tsfsNode &desNode)
	{
		desNode.swapBits = srcNode.swapBits;
		desNode.id = srcNode.id;
		desNode.parentId = srcNode.parentId;
		desNode.leftId = srcNode.leftId;       
		desNode.rightId = srcNode.rightId;    
		desNode.type = srcNode.type;        
		desNode.state = srcNode.state;   
		desNode.nameLength = srcNode.nameLength;
		desNode.dataLength = srcNode.dataLength;
		desNode.signedDataLength = srcNode.signedDataLength;
		desNode.macDataLength = srcNode.macDataLength;
		desNode.dataEncryMethod = srcNode.dataEncryMethod;
		memcpy((char *)desNode.name,(char *)srcNode.name, srcNode.nameLength);
		memcpy((char *)desNode.signedData, (char *)srcNode.signedData, srcNode.signedDataLength);
		memcpy((char *)desNode.data, (char *)srcNode.data, srcNode.dataLength);
		memcpy((char *)desNode.macData, (char *)srcNode.macData, srcNode.macDataLength);
	}
    
    static std::string simplifiedKey(const std::string &key, bool pubKey)
    {
        std::string result;
        std::string beginFlag;
        std::string endFlag;
        if (pubKey)
        {
            beginFlag = "-----BEGIN PUBLIC KEY-----\n";
            endFlag = "\n-----END PUBLIC KEY-----";
        }
        else
        {
            beginFlag = "-----BEGIN PRIVATE KEY-----\n";
            endFlag = "\n-----END PRIVATE KEY-----";
        }
        std::string::size_type pos = key.find(endFlag);
        if (pos != string::npos)
        {
            result = key.substr(0, pos);
            replace(result, beginFlag, "");
            replace(result, "\n", "");
        }
        return result;
    }
    
    static std::string reductKey(const std::string &key, const bool pubkey = true) {
        std::string beginFlag = pubkey ? "-----BEGIN PUBLIC KEY-----\n" : "-----BEGIN PRIVATE KEY-----\n";
        std::string endFlag = pubkey ? "\n-----END PUBLIC KEY-----" : "\n-----END PRIVATE KEY-----";
        
        int32_t keyLen = (int32_t)key.length();
        std::string result = key;
        for (int32_t i = 64; i < keyLen; i += 64) {
            if (result[i] != '\n') {
                result.insert(i, "\n");
            }
            
            i++;
        }
        
        result.insert(0, beginFlag);
        result.append(endFlag);
        
        return result;
    }
    
    static std::string sm9_simplifiedKey(const std::string &key, bool pubKey) {
//        -----BEGIN SM9 PRIVATE KEY-----
        std::string result;
        std::string beginFlag;
        std::string endFlag;
        if (pubKey)
        {
            beginFlag = "-----BEGIN SM9 PUBLIC KEY-----\n";
            endFlag = "\n-----END SM9 PUBLIC KEY-----";
        }
        else
        {
            beginFlag = "-----BEGIN SM9 PRIVATE KEY-----\n";
            endFlag = "\n-----END SM9 PRIVATE KEY-----";
        }
        std::string::size_type pos = key.find(endFlag);
        if (pos != string::npos)
        {
            result = key.substr(0, pos);
            replace(result, beginFlag, "");
            replace(result, "\n", "");
        }
        return result;
    }
    
    static std::string sm9_reductKey(const std::string &key, const bool pubkey = true) {
        std::string beginFlag = pubkey ? "-----BEGIN SM9 PUBLIC KEY-----\n" : "-----BEGIN SM9 PRIVATE KEY-----\n";
        std::string endFlag = pubkey ? "\n-----END SM9 PUBLIC KEY-----" : "\n-----END SM9 PRIVATE KEY-----";
        
        int32_t keyLen = (int32_t)key.length();
        std::string result = key;
        for (int32_t i = 64; i < keyLen; i += 64) {
            if (result[i] != '\n') {
                result.insert(i, "\n");
            }
            
            i++;
        }
        
        result.insert(0, beginFlag);
        result.append(endFlag);
        
        return result;
    }
};
#endif
