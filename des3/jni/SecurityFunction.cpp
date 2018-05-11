//
// Created by zack on 2018/4/8.
//

#include "SecurityFunction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <android/log.h>
#include "Base64.h"
#include "DES.h"
#include "MD5.h"

#define LOG_TAG "Security"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

//应用签名的md5值
const char *APPSIGN = "32a3ff9ef61823348ba996c2f5adb394";

jstring getLoochaJsSign(JNIEnv *env, jobject object, jstring mobile,jstring model, jstring time, jstring type, jstring server_did){
      isAppSignCorrect(env);
      const char *mobileStr = env->GetStringUTFChars(mobile, false);
      const char *modelStr = env->GetStringUTFChars(model, false);
      const char *timeStr = env->GetStringUTFChars(time, false);
      const char *typeStr = env->GetStringUTFChars(type, false);
      const char *server_didStr = env->GetStringUTFChars(server_did, false);
      char buffer[256];
      snprintf(buffer,sizeof(buffer),"mobile=%s&model=%s&server_did=%s&time=%s&type=%s",mobileStr,modelStr,server_didStr,timeStr,typeStr);
      env->ReleaseStringUTFChars(mobile, mobileStr);
      env->ReleaseStringUTFChars(model, modelStr);
      env->ReleaseStringUTFChars(time, timeStr);
      env->ReleaseStringUTFChars(type, typeStr);
      env->ReleaseStringUTFChars(server_did, server_didStr);
      MD5 md5 = MD5(buffer);
      std::string md5Result = md5.hexdigest();
      return env->NewStringUTF(md5Result.c_str());
  }


jstring getLoochaCommonSign(JNIEnv *env, jobject object, jstring mobile,jstring model,jstring provinceId ,jstring time, jstring type, jstring server_did){
      isAppSignCorrect(env);
      const char *mobileStr = env->GetStringUTFChars(mobile, false);
      const char *modelStr = env->GetStringUTFChars(model, false);
      const char *provinceIdStr = env->GetStringUTFChars(provinceId, false);
      const char *timeStr = env->GetStringUTFChars(time, false);
      const char *typeStr = env->GetStringUTFChars(type, false);
      const char *server_didStr = env->GetStringUTFChars(server_did, false);
      char buffer[256];
      snprintf(buffer,sizeof(buffer),"mobile=%s&model=%s&provinceId=%s&server_did=%s&time=%s&type=%s",mobileStr,modelStr,provinceIdStr,server_didStr,timeStr,typeStr);
      env->ReleaseStringUTFChars(mobile, mobileStr);
      env->ReleaseStringUTFChars(model, modelStr);
      env->ReleaseStringUTFChars(provinceId, provinceIdStr);
      env->ReleaseStringUTFChars(time, timeStr);
      env->ReleaseStringUTFChars(type, typeStr);
      env->ReleaseStringUTFChars(server_did, server_didStr);
      MD5 md5 = MD5(buffer);
      std::string md5Result = md5.hexdigest();
      return env->NewStringUTF(md5Result.c_str());
  }


jstring getLoochaScanSign(JNIEnv *env, jobject object,jstring qrcode, jstring mobile,jstring password){
      isAppSignCorrect(env);
      const char *qrcodeStr = env->GetStringUTFChars(qrcode, false);
      const char *mobileStr = env->GetStringUTFChars(mobile, false);
      const char *passwordStr = env->GetStringUTFChars(password, false);
      char buffer[256];
      snprintf(buffer,sizeof(buffer),"%s&password=%s&mobile=%s",qrcodeStr,passwordStr,mobileStr);
      env->ReleaseStringUTFChars(qrcode, qrcodeStr);
      env->ReleaseStringUTFChars(mobile, mobileStr);
      env->ReleaseStringUTFChars(password, passwordStr);
      MD5 md5 = MD5(buffer);
      std::string md5Result = md5.hexdigest();
      return env->NewStringUTF(md5Result.c_str());
  }


jstring getLoochaXX(JNIEnv *env, jobject object){
  //最终签名的MD5
  jstring md5Sign = getAppSign(env);
  const char * md5SignChar = env->GetStringUTFChars(md5Sign, false);
  //签名对比
  int result = strcmp(md5SignChar,APPSIGN);
  env->ReleaseStringUTFChars(md5Sign, md5SignChar);
  if(result != 0){
     exitApplication(env);
  }
  return md5Sign;
}

/**
获取签名md5后
**/
jstring getAppSign(JNIEnv *env){
  const char *signatureChars = getAppUnEncryptSign(env);
  if(signatureChars != NULL){
    MD5 md5 = MD5(signatureChars);
    return  env->NewStringUTF(md5.hexdigest().c_str());
  }
  return NULL;
}

//获取未md5加密应用签名
const char * getAppUnEncryptSign(JNIEnv* env){
  jobject context;
  jclass localClass = env->FindClass("android/app/ActivityThread");
  if (localClass != NULL){
      jmethodID getapplication = env->GetStaticMethodID(localClass, "currentApplication", "()Landroid/app/Application;");
      if (getapplication != NULL){
          context = env->CallStaticObjectMethod(localClass, getapplication);
          if(context != NULL){
            jclass  activity = env->GetObjectClass(context);
            jmethodID methodID_func = env->GetMethodID(activity, "getPackageManager", "()Landroid/content/pm/PackageManager;");
            jobject packageManager = env->CallObjectMethod(context,methodID_func);
            jclass packageManagerclass = env->GetObjectClass(packageManager);
            jmethodID methodID_pack = env->GetMethodID(activity,"getPackageName", "()Ljava/lang/String;");
            jstring name_str = (jstring)(env->CallObjectMethod(context, methodID_pack));
            jmethodID methodID_pm = env->GetMethodID(packageManagerclass,"getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
            jobject package_info = env->CallObjectMethod(packageManager, methodID_pm, name_str, 64);
            jclass package_infoclass = env->GetObjectClass(package_info);
            jfieldID fieldID_signatures = env->GetFieldID(package_infoclass,"signatures", "[Landroid/content/pm/Signature;");
            jobject signatur = env->GetObjectField(package_info, fieldID_signatures);
            jobjectArray  signatures = (jobjectArray)(signatur);
            jobject signature = env->GetObjectArrayElement(signatures, 0);
            jclass signature_clazz = env->GetObjectClass(signature);
            jmethodID toString_methodId = env->GetMethodID(signature_clazz, "toCharsString", "()Ljava/lang/String;");
            jstring signature_CharsString = (jstring) env->CallObjectMethod(signature, toString_methodId);
            return env->GetStringUTFChars(signature_CharsString, false);
          }
      }
  }
  return NULL;
}

char* HexStrToByte(const char* source){
	short i;
	int highByte, lowByte;
	int sourceLen = strlen(source);
	char* result = new char[sourceLen/2];
	int j =0;
	for (i = 0; i < sourceLen; i += 2){
		highByte = toupper(source[i]);
		lowByte  = toupper(source[i + 1]);
		if (highByte > '9')
			highByte -= '7';
		else
			highByte -= '0';
		if (lowByte > '9')
			lowByte -= '7';
		else
			lowByte -= '0';
		result[j] = (highByte << 4) | lowByte;
        j++;
	}
	return result;
}

//获取时间签名
const char* getSignTimeEncrypt(JNIEnv *env,const char* time){
    int timeLength = strlen(time);
    if(timeLength < 13){
        LOGE("time=%s",time);
        return '\0';
    }

    const char *signatureChars = getAppUnEncryptSign(env);
    char * signatureCharsStr = HexStrToByte(signatureChars);
    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(signatureCharsStr), strlen(signatureChars)/2);

    const char *keyStore =  encoded.c_str();
    int keyStoreLength = strlen(keyStore);
    char * index = (char*) malloc (sizeof(char)*(4+1));
    strncpy(index, time+3, 4);
    index[4]='\0';
    char * len = (char*) malloc (sizeof(char)*(5+1));
    strncpy(len, time+timeLength-6, 5);
    len[5]='\0';
    int indexInt = atoi(index);
    int lenInt = atoi(len);
    int start = indexInt % keyStoreLength;
    int length = lenInt / keyStoreLength;
    if(length < 8) {
        length = 8;
    }
    if(start + length > keyStoreLength) {
         start = keyStoreLength - length;
    }
    char * result = (char*) malloc (sizeof(char)*(length+1));
    strncpy(result, keyStore+start, length);
    result[length]='\0';
    free(index);
    free(len);
    return result;
}

jstring getLoochaNewSign(JNIEnv *env, jobject object, jstring type, jstring time, jstring path, jstring mobile,
    jstring server_did, jstring app, jstring model){
    isAppSignCorrect(env);
    const char *mobileStr = env->GetStringUTFChars(mobile, false);
    const char *modelStr = env->GetStringUTFChars(model, false);
    const char *timeStr = env->GetStringUTFChars(time, false);
    const char *typeStr = env->GetStringUTFChars(type, false);
    const char *server_didStr = env->GetStringUTFChars(server_did, false);
    const char *pathStr = env->GetStringUTFChars(path, false);
    const char *appStr = env->GetStringUTFChars(app, false);
    const char *keyStoreStr = getSignTimeEncrypt(env,timeStr);
    char buffer[512];
    snprintf(buffer,sizeof(buffer),"app=%s&mobile=%s&model=%s&path=%s&server_did=%s&time=%s&type=%s%s",
    appStr,mobileStr,modelStr,pathStr,server_didStr,timeStr,typeStr,keyStoreStr);
    env->ReleaseStringUTFChars(mobile, mobileStr);
    env->ReleaseStringUTFChars(model, modelStr);
    env->ReleaseStringUTFChars(time, timeStr);
    env->ReleaseStringUTFChars(type, typeStr);
    env->ReleaseStringUTFChars(server_did, server_didStr);
    env->ReleaseStringUTFChars(path, pathStr);
    env->ReleaseStringUTFChars(app, appStr);
    MD5 md5 = MD5(buffer);
    std::string md5Result = md5.hexdigest();
    return env->NewStringUTF(md5Result.c_str());
}

jbyteArray getLoochaDecryptResult(JNIEnv *env, jobject object, jbyteArray encryptData,jstring time){
     isAppSignCorrect(env);
     const char *timeStr = env->GetStringUTFChars(time,false);
     const char *keyStoreStr = getSignTimeEncrypt(env,timeStr);
     env->ReleaseStringUTFChars(time, timeStr);
     int encryptDataLength = env->GetArrayLength(encryptData);
     jbyte * encryptDataBytes = env->GetByteArrayElements(encryptData, 0);
     char * encryptDataChars = new char[encryptDataLength + 1];
     memset(encryptDataChars,0,encryptDataLength + 1);
     memcpy(encryptDataChars, encryptDataBytes, encryptDataLength);
     encryptDataChars[encryptDataLength] = '\0';
     env->ReleaseByteArrayElements(encryptData, encryptDataBytes, 0);
     char * resultData = new char[encryptDataLength + 1];
     memset(resultData,0,encryptDataLength + 1);
     long resultDataLength = 0;
     int flag = decryptdes(resultData,&resultDataLength,encryptDataChars,encryptDataLength,keyStoreStr);
     if(flag < 0){  //解密失败
        LOGE("decryptdes --- fail");
        return NULL;
     }
     jbyteArray result = env->NewByteArray(resultDataLength);
     jbyte *ibyteResult = env->GetByteArrayElements(result,0);
     memcpy(ibyteResult,resultData,resultDataLength);
     env->SetByteArrayRegion(result, 0,resultDataLength,ibyteResult);
     return result;
}

/**
验证签名正确性，不正确直接退出应用
**/
void isAppSignCorrect(JNIEnv *env){
  //最终签名的MD5
  jstring md5Sign = getAppSign(env);
  const char * md5SignChar = env->GetStringUTFChars(md5Sign, false);
  //签名对比
  int result = strcmp(md5SignChar,APPSIGN);
  if(result != 0){
     exitApplication(env);
  }
}

/**
退出应用
*/
void exitApplication(JNIEnv *env){
    jclass temp_clazz = env->FindClass("java/lang/System");
    jmethodID mid_static_method = env->GetStaticMethodID(temp_clazz,"exit","(I)V");
    env->CallStaticVoidMethod(temp_clazz,mid_static_method,0);
    env->DeleteLocalRef(temp_clazz);
}