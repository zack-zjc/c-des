
#include <stdio.h>
#include <string.h>
#include <android/log.h>
#include <stddef.h>
#include <jni.h>
#include "SecurityFunction.h"
#define LOG_TAG "Security"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)


/**
jni对应注册方法start
*/

JNIEXPORT  jbyteArray JNICALL decryptTelecomResult(JNIEnv *env, jobject object,jbyteArray result,jstring time){
    return getLoochaDecryptResult(env,object,result,time);
}

/**
jni对应注册方法end
*/

//java对应的class
static const char* javaClass="java类名";

//方法数组，JNINativeMethod的第一个参数是Java中的方法名，第二个参数是函数签名即参数，第三个参数是对应的c方法指针。
//Java方法的签名一定要与对应的C++方法参数类型一致，否则注册方法可能失败。
static JNINativeMethod method_table[] = {
        {"decryptResult",       "([BLjava/lang/String;)[B",
                                (void *) decryptTelecomResult}

};

//动态注册方法
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->AttachCurrentThread(&env, NULL) == JNI_OK) {
       //获取对应声明native方法的Java类
      jclass  clazz = env->FindClass(javaClass);
        if (clazz == NULL) {
            return JNI_FALSE;
        }
        //动态注册方法
        if (env->RegisterNatives(clazz, method_table, sizeof(method_table)/ sizeof(method_table[0])) == JNI_OK) {
            return JNI_VERSION_1_4;
        }
    }
    return JNI_FALSE;
}


