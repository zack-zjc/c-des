//
// Created by zack on 2018/4/8.
//

#include "SecurityFunction.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
long long APP_SHIFT = 0;

/**
获取签名md5后
**/
jstring getAppSign(JNIEnv *env){
  const char *signatureChars = getAppUnEncryptSign(env);
  if(signatureChars != NULL){
    MD5 md5 = MD5(signatureChars);
    return  env->NewStringUTF(md5.hexdigest().c_str());
  }
  char * result = "493bda5f2c699ab84332816fe9ff3a23";
  return env->NewStringUTF(result);
}

//获取未md5加密应用签名
const char * getAppUnEncryptSign(JNIEnv* env){
  jobject context;
  jclass localClass = env->FindClass("com/realcloud/loochadroid/ApplicationContext");
  if (localClass != NULL){
      jmethodID getapplication = env->GetStaticMethodID(localClass, "getNativeContext", "()Landroid/app/Application;");
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

/**
验证签名正确性，不正确直接退出应用
**/
void isAppSignCorrect(JNIEnv *env){
  //最终签名的MD5
  jstring md5Sign = getAppSign(env);
  if(md5Sign != NULL){
    const char * md5SignChar = env->GetStringUTFChars(md5Sign, false);
      //签名对比
      int result = strcmp(md5SignChar,APPSIGN);
      if(result != 0){
         exitApplication(env);
      }
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

//设置时间签名偏移量
void setLoochaInfo(JNIEnv *env, jobject jobject, jlong shift){
    APP_SHIFT = shift;
    isAppTraced(env);
    return;
}

//当前app是否被调试读取TracerPid不为0表示被调试
void isAppTraced(JNIEnv *env){
    char *traceStr="TracerPid:";
    char blank = '\0';
    char statusFile[100];
    snprintf(statusFile,sizeof(statusFile),"/proc/%d/status",getpid());
    FILE * fd = fopen(statusFile,"r");
    int tracePid = 0;
    if(fd != NULL){
       char buffer[50];
       int continueRead = 1;
       int size = 0;
       do{
         size = fread(buffer, sizeof(char), 50 , fd);
         if(strstr(buffer,traceStr)){
            char *subStr = strstr(buffer,traceStr);
            char * tempStr = (char*) malloc (sizeof(char)*(10+1));
            strncpy(tempStr, subStr+10, 10);
            tempStr[11]='\0';
            for (int i = 0; i < 10; i++){
               if(tempStr[i] != blank){
                   char charStr[2];
                   snprintf(charStr,sizeof(charStr),"%c",tempStr[i]);
                   tracePid = atoi(charStr);
                   continueRead = 0;
                   break;
               }
            }
         }
       }while(continueRead == 1 && size != 0);
       LOGE("trace=%d",tracePid);
       fclose(fd);
    }
    if(tracePid != 0){ //当前被调试
        APP_SHIFT = 0;
       //exitApplication(env);
    }
}