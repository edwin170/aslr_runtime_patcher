THEOS_DEVICE_IP = -p 2222 root@localhost
ARCHS = arm64 arm64e
export SYSROOT = $(THEOS)/sdks/iPhoneOS16.5.sdk
TARGET := iphone:clang:16.5:12.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = aslrruntimepatcher

aslrruntimepatcher_FILES = main.m getBootManifest.c
aslrruntimepatcher_CFLAGS = -fobjc-arc -Wno-error=unused-variable -Wno-error=unused-function
aslrruntimepatcher_LDFLAGS += -L. libkrw.tbd
aslrruntimepatcher_CODESIGN_FLAGS = -Sentitlements.plist
aslrruntimepatcher_FRAMEWORKS = Foundation IOKit

aslrruntimepatcher_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk
