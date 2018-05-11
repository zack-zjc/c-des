LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := Security

LOCAL_SRC_FILES =: SecurityFunction.cpp \
                   MD5.cpp \
                   Base64.cpp \
                   Jni.cpp \
                   DES.cpp \


LOCAL_LDLIBS :=-llog

include $(BUILD_SHARED_LIBRARY)
