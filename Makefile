ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = Calculator

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = sshh
sshh_FILES = Tweak.xm
sshh_CFLAGS = -fobjc-arc
sshh_FRAMEWORKS = UIKit Foundation QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
