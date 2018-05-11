/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>

#ifndef SecurityFunction
#define SecurityFunction
#ifdef __cplusplus
extern "C" {
#endif

//江苏一键上网签名
jstring getLoochaJsSign(JNIEnv *, jobject, jstring, jstring, jstring, jstring, jstring);

//其他省份一键上网签名
jstring getLoochaCommonSign(JNIEnv *, jobject, jstring, jstring, jstring, jstring, jstring, jstring);

//扫码通用签名
jstring getLoochaScanSign(JNIEnv *, jobject, jstring,jstring, jstring);

//获取请求头部签名
jstring getLoochaXX(JNIEnv*, jobject);

//获取应用签名
jstring getAppSign(JNIEnv*);

//获取未md5加密应用签名
const char* getAppUnEncryptSign(JNIEnv*);

//获取时间签名
const char* getSignTimeEncrypt(JNIEnv *env,const char*);

//获取签名
jstring getLoochaNewSign(JNIEnv *, jobject, jstring, jstring, jstring, jstring, jstring, jstring, jstring);

//解密结果
jbyteArray getLoochaDecryptResult(JNIEnv *, jobject, jbyteArray ,jstring);

void exitApplication(JNIEnv*);

void isAppSignCorrect(JNIEnv*);

#ifdef __cplusplus
}

#endif
#endif