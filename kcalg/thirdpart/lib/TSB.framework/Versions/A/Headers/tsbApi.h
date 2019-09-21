#ifndef __TSB_H_
#define __TSB_H_

#include <map>
#include <vector>
#include <memory>
#include <chrono>
#include <functional>
#include <string>
#include "tsbCommonApi.h"

using namespace std;
using namespace std::chrono;


#define TSB_BACKUP_REQ_COMMAND  0x0001
#define TSB_BACKUP_RESP_COMMAND 0x0002
#define TSB_GET_RK_REQ_COMMAND  0x0003   
#define TSB_GET_RK_RESP_COMMAND 0x0004

namespace tsb
{
	typedef enum _CAlg
	{
		NONE = -1,
		TECC = 0,
		TAES128CBC,
		TECCSTAND,
		TECCBitcoin,
		TSM2
	} tsbCryptAlgType;

	typedef enum _CPwd
	{
		LoginKey = 0,
		SafeKey,
	}tsbPwd;

	typedef struct _PCHeader
	{
		std::string uid;
		std::string version;
		std::string tips;
		std::string description;
		int64_t createtime;
	}tsbPCHeader;

	typedef struct tsbServerParam
	{
		std::string deviceId;
		std::string deviceType;
		std::string plarform;
		std::string encKey;
		std::string salt1;
		std::string salt2;
		int32_t signType;
	} TNTSBServerParam;

	typedef std::function<int64_t(std::string tid,int64_t code,std::string &key, tsbPwd type)> KeyCallBack;
	
	class ITSBSDK
	{
	public:
		/*
		tsbGetPubKey
		@description:get object's pub key.
		@param crypt[OUT]:alg type,pubKey[OUT]:pubkey
		@return errcode
		*/
		virtual int64_t tsbGetPubKey(BufferArray &pubKey, std::string &cTime) = 0;
		/*
		tsbEncryptData
		@description:encrypt data
		@param crypt[IN] : encrypt alg ,plainText[IN]: plain data,key[IN]:the encrypt key. if the alg type is symmetric alg, the key will used
		,buffer [OUT]: recieve the encrypt data
		@return errcode
		*/
		virtual int64_t tsbEncryptData(tsbCryptAlgType crypt,const BufferArray &plainText, BufferArray & buffer ) = 0;
		/*
		tsbDecryptData
		@description:decrypt data
		@param crypt[IN] : encrypt alg ,secBuffer[IN]: secret data,key[IN]:the encrypt key. if the alg type is symmetric alg, the key will used
		,plainText [OUT]: recieve the plain data
		@return errcode
		*/
		virtual int64_t tsbDecryptData(tsbCryptAlgType crypt,const BufferArray &secBuffer, BufferArray & plainText ) = 0;
		/*
		tsbSignature
		@description:signature for data
		@param context[IN]: be signed data
		,sigBuffer [OUT]: recieve the sign data
		@return errcode
		*/
		virtual int64_t tsbSignature(const BufferArray &context, BufferArray & sigBuffer ) = 0;
		/*
		tsbVerifySignature
		@description:verify signature for data
		@param context[IN]: be signed data
		,sigBuffer [IN]:  sign data
		@return errcode
		*/
		virtual int64_t tsbVerifySignature(const BufferArray &context, const BufferArray &sigBuffer,const char *pubKey =NULL) = 0;
		/*
		tsbGetBkCFS
		@description:get the cfg back file
		@param safeKey[IN] : safe code ,bkPath[OUT]:back up path
		@return errcode
		*/
		virtual int64_t tsbGetBkCFS(BufferArray &bkPath,const char *tips = NULL) = 0;
		virtual int64_t tsbGetBkCFSWithRK(BufferArray &bkPath, const char *RK,const char *tip = NULL) = 0;
		/*
		tsbRestoreCFS
		@description:restore back file for a object
		@param safeKey[IN] : safe code ,tsfsFolder[IN]:cfg folder,bkCFS[IN]: back file
		@return errcode.
		*/
		virtual int64_t tsbRestoreCFS(const char *bkCFS) = 0;
		virtual int64_t tsbRestoreCFSWithRK(const char *bkCFS, const char *RK) = 0;
		/*
		tsbCheckLoginKey
		@description:check login key
		@param oldPwd[IN] : old password
		@return errcode.
		*/
		virtual int64_t tsbCheckLoginKey(const char *oldPwd) = 0;
		/*
		getTSBInfoTServer
		@description:get tsb info
		@param param[out] : tsbinfo,type[IN]:request type
		@return errcode.
		*/
		virtual int64_t tsbGetSafeInfoTServer(TNTSBServerParam &param, const char *serverPub, int32_t type) = 0;
	};
	/////////////////////////////////Notice///////////////////////////////
	/////SHOULD CALL setCallBack & setTSBSDKFolder BEFORE INITSDK/////////
	//////////////////////////////////////////////////////////////////////
	/*
	set TSB SDKFolder,
	*/
	int64_t setCallBack(KeyCallBack callBack);
	int64_t setTSBSDKFolder(const char *tsbFolder);
	/*
	init sdk ogject
	*/
	shared_ptr<ITSBSDK> initTSBSDK(const char *tid, tsbCryptAlgType alg,const char *description = NULL);
	/*
	uninit sdk object
	*/
	void destoryTSBSDK(string temail = "");
	/*
	get default UID
	*/
	std::string  getTSBCommonUid();
	/*
	@get latest err code
	*/
	int64_t getLatestErrCode();
	/*
	common asymmetrical encry interface
	*/
	int64_t tsbASYEncryptData(tsbCryptAlgType crypt, const BufferArray &pubKey,const BufferArray &plainText, BufferArray & buffer);
	/*
	common symmetrical encry interface
	*/
	int64_t tsbSYEncryptData(tsbCryptAlgType crypt, const BufferArray &key,   const BufferArray &plainText, BufferArray & buffer);
	int64_t tsbSYDecryptData(tsbCryptAlgType crypt, const BufferArray &key,   const BufferArray &secBuffer, BufferArray & plainText);
	/*
	get backfile info,std::map<std::string, tsbPCHeader> key: filepath,value: info
	*/
	void tsbGetBackFileInfo(std::vector<std::string> files,std::map<std::string, tsbPCHeader> &infos);
	/*
	batch reset login key
	@uids: temail list
	@oldkey :old pwd
	@newKey: new pwd
	@return true or false
	*/
	bool tsbBatchResetLoginKey(const std::vector<std::string> &uids, const char *oldKey, const char * newKey);
    
}
#endif
