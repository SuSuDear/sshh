ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = Calculator

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = sshh

sshh_FILES = Tweak.xm
sshh_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-deprecated-declarations
sshh_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 Calculator 2>/dev/null || true"
