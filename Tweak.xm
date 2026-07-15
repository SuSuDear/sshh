//
// sshh — 任意激活码通过
//
// 行为：
//   1. 启动后不自动进主页
//   2. 输入任意非空激活码
//   3. 点击「验证 / 确定 / 激活 / 提交」后本地标记已激活
//   4. 欢迎页校验直接通过并进入主页
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <substrate.h>

#pragma mark - IDA 偏移（imagebase = 0x100000000）

static const uintptr_t kPrimaryCheckOff   = 0x8C904;   // 主校验
static const uintptr_t kSecondaryCheckOff = 0x8C7A8;   // 次校验
static const uintptr_t kPrimaryFlagOff    = 0x10E5600; // dword_1010E5600
static const uintptr_t kSecondaryFlagOff  = 0x10E55F0; // dword_1010E55F0
static const uintptr_t kImageBase         = 0x100000000ULL;

#pragma mark - 日志

#ifndef SSHH_LOG
#define SSHH_LOG 1
#endif

#if SSHH_LOG
#define SSHHLog(fmt, ...) NSLog(@"[sshh] " fmt, ##__VA_ARGS__)
#else
#define SSHHLog(fmt, ...)
#endif

#pragma mark - 声明

@interface TSHWelcomeViewController : UIViewController
- (BOOL)tsh_didEnterHome;
- (void)tsh_checkActivationAndEnterHome;
- (void)ToHome:(BOOL)animated;
- (UILabel *)tsh_statusLabel;
- (UIActivityIndicatorView *)tsh_loading;
@end

#pragma mark - 状态

static BOOL gUserUnlocked = NO;     // 用户是否已提交非空激活码
static BOOL gSlideReady = NO;
static BOOL gCheckHooksReady = NO;
static intptr_t gSlide = 0;

typedef int (*ZCCheckFn)(void);
static ZCCheckFn orig_primary_check = NULL;
static ZCCheckFn orig_secondary_check = NULL;

#pragma mark - 工具

static BOOL SSHHIsCalculatorProcess(void) {
    NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSString *exe = NSBundle.mainBundle.executablePath.lastPathComponent ?: @"";
    return [bid isEqualToString:@"com.apple.calculator"] ||
           [exe isEqualToString:@"Calculator"];
}

// 解析主程序 slide
static BOOL SSHHEnsureSlide(void) {
    if (gSlideReady) return YES;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || strstr(name, "sshh") != NULL) continue;

        BOOL hit = (strstr(name, "/Calculator.app/Calculator") != NULL);
        if (!hit && strstr(name, "PersistenceHelper") != NULL && strstr(name, ".dylib") == NULL) {
            hit = YES;
        }
        if (!hit) continue;

        gSlide = _dyld_get_image_vmaddr_slide(i);
        gSlideReady = YES;
        SSHHLog("image=%s slide=0x%lx", name, (unsigned long)gSlide);
        return YES;
    }

    if (count > 0) {
        const char *name = _dyld_get_image_name(0);
        gSlide = _dyld_get_image_vmaddr_slide(0);
        gSlideReady = YES;
        SSHHLog("fallback image=%s slide=0x%lx", name ? name : "(null)", (unsigned long)gSlide);
        return YES;
    }
    return NO;
}

static void *SSHHAddr(uintptr_t fileOff) {
    if (!SSHHEnsureSlide()) return NULL;
    return (void *)(kImageBase + fileOff + (uintptr_t)gSlide);
}

// 写库内激活成功标志
static void SSHHWriteActivationFlags(void) {
    volatile int *primaryFlag = (volatile int *)SSHHAddr(kPrimaryFlagOff);
    volatile int *secondaryFlag = (volatile int *)SSHHAddr(kSecondaryFlagOff);
    if (primaryFlag) *primaryFlag = 1;
    if (secondaryFlag) *secondaryFlag = 1;
    SSHHLog("flags written p=%p s=%p", primaryFlag, secondaryFlag);
}

#pragma mark - 底层校验 hook

static int hooked_primary_check(void) {
    if (gUserUnlocked) {
        SSHHLog("primary -> 1");
        return 1;
    }
    return orig_primary_check ? orig_primary_check() : 0;
}

static int hooked_secondary_check(void) {
    if (gUserUnlocked) {
        SSHHLog("secondary -> 1");
        return 1;
    }
    return orig_secondary_check ? orig_secondary_check() : 0;
}

static BOOL SSHHInstallCheckHooks(void) {
    if (gCheckHooksReady) return YES;
    if (!SSHHEnsureSlide()) return NO;

    void *primary = SSHHAddr(kPrimaryCheckOff);
    void *secondary = SSHHAddr(kSecondaryCheckOff);
    if (!primary || !secondary) return NO;

    SSHHLog("MSHook primary=%p secondary=%p", primary, secondary);
    MSHookFunction(primary, (void *)hooked_primary_check, (void **)&orig_primary_check);
    MSHookFunction(secondary, (void *)hooked_secondary_check, (void **)&orig_secondary_check);
    gCheckHooksReady = YES;
    return YES;
}

#pragma mark - 收集激活码 / 欢迎页

static void SSHHCollectTextFields(UIView *view, NSMutableArray<NSString *> *outCodes) {
    if (!view || view.hidden || view.alpha < 0.01) return;

    if ([view isKindOfClass:[UITextField class]]) {
        UITextField *tf = (UITextField *)view;
        NSString *text = [tf.text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (text.length > 0) {
            [outCodes addObject:text];
        }
    }
    for (UIView *sub in view.subviews) {
        SSHHCollectTextFields(sub, outCodes);
    }
}

static NSArray<UIWindow *> *SSHHAllWindows(void) {
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w) [windows addObject:w];
            }
        }
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w && ![windows containsObject:w]) [windows addObject:w];
    }
    UIWindow *key = UIApplication.sharedApplication.keyWindow;
    if (key && ![windows containsObject:key]) [windows addObject:key];
#pragma clang diagnostic pop
    return windows;
}

static NSString *SSHHCurrentActivationCode(void) {
    NSMutableArray<NSString *> *codes = [NSMutableArray array];
    for (UIWindow *w in SSHHAllWindows()) {
        SSHHCollectTextFields(w, codes);
    }
    // 取最后一个非空输入，通常是前台激活框
    for (NSInteger i = (NSInteger)codes.count - 1; i >= 0; i--) {
        if (codes[i].length > 0) return codes[i];
    }
    return nil;
}

static TSHWelcomeViewController *SSHHFindWelcomeVC(UIViewController *vc) {
    if (!vc) return nil;
    if ([vc isKindOfClass:NSClassFromString(@"TSHWelcomeViewController")]) {
        return (TSHWelcomeViewController *)vc;
    }
    for (UIViewController *child in vc.childViewControllers) {
        TSHWelcomeViewController *found = SSHHFindWelcomeVC(child);
        if (found) return found;
    }
    if (vc.presentedViewController) {
        return SSHHFindWelcomeVC(vc.presentedViewController);
    }
    return nil;
}

static TSHWelcomeViewController *SSHHGetWelcomeVC(void) {
    if (!NSClassFromString(@"TSHWelcomeViewController")) return nil;
    for (UIWindow *w in SSHHAllWindows()) {
        TSHWelcomeViewController *found = SSHHFindWelcomeVC(w.rootViewController);
        if (found) return found;
    }
    return nil;
}

// 标记解锁并尝试进入主页
static void SSHHUnlockWithCode(NSString *code, NSString *reason) {
    if (code.length == 0) {
        SSHHLog("empty code ignored (%@)", reason);
        return;
    }

    BOOL first = !gUserUnlocked;
    gUserUnlocked = YES;
    SSHHWriteActivationFlags();
    SSHHLog("%s unlock code=%@ reason=%@", first ? "FIRST" : "again", code, reason);

    dispatch_async(dispatch_get_main_queue(), ^{
        TSHWelcomeViewController *welcome = SSHHGetWelcomeVC();
        if (!welcome) {
            SSHHLog("welcome vc missing, wait poll");
            return;
        }
        if ([welcome respondsToSelector:@selector(tsh_didEnterHome)] && [welcome tsh_didEnterHome]) {
            return;
        }
        if ([welcome respondsToSelector:@selector(tsh_statusLabel)]) {
            UILabel *label = [welcome tsh_statusLabel];
            if ([label isKindOfClass:[UILabel class]]) {
                label.text = @"激活成功，正在进入…";
            }
        }
        if ([welcome respondsToSelector:@selector(tsh_loading)]) {
            UIActivityIndicatorView *loading = [welcome tsh_loading];
            if ([loading respondsToSelector:@selector(stopAnimating)]) {
                [loading stopAnimating];
            }
        }
        // 直接走欢迎页检查入口（内部会看到 primary=1）
        if ([welcome respondsToSelector:@selector(tsh_checkActivationAndEnterHome)]) {
            [welcome tsh_checkActivationAndEnterHome];
        } else if ([welcome respondsToSelector:@selector(ToHome:)]) {
            [welcome ToHome:YES];
        }
    });
}

static BOOL SSHHIsVerifyTitle(NSString *title) {
    if (title.length == 0) return NO;
    title = [title stringByTrimmingCharactersInSet:
             [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return [title isEqualToString:@"验证"] ||
           [title isEqualToString:@"确定"] ||
           [title isEqualToString:@"激活"] ||
           [title isEqualToString:@"提交"] ||
           [title isEqualToString:@"OK"] ||
           [title isEqualToString:@"Confirm"];
}

// 从控件上尽量取展示文案
static NSString *SSHHControlTitle(UIControl *control) {
    if ([control isKindOfClass:[UIButton class]]) {
        UIButton *btn = (UIButton *)control;
        if (btn.currentTitle.length > 0) return btn.currentTitle;
        NSAttributedString *attr = btn.currentAttributedTitle;
        if (attr.string.length > 0) return attr.string;
    }
    if (control.accessibilityLabel.length > 0) return control.accessibilityLabel;
    // 再扫一层子 label
    for (UIView *sub in control.subviews) {
        if ([sub isKindOfClass:[UILabel class]]) {
            NSString *t = ((UILabel *)sub).text;
            if (t.length > 0) return t;
        }
    }
    return nil;
}

#pragma mark - 点击验证按钮

%hook UIControl

// 所有 UIButton 最终都走这里，只 hook 一次避免重复
- (void)sendAction:(SEL)action to:(id)target forEvent:(UIEvent *)event {
    if (SSHHIsCalculatorProcess()) {
        // 只关心 touchUp 类事件，减少误触发
        UIEventType type = event.type;
        BOOL lookLikeTouchUp = (event == nil) || (type == UIEventTypeTouches);
        if (lookLikeTouchUp) {
            NSString *title = SSHHControlTitle(self);
            if (SSHHIsVerifyTitle(title)) {
                NSString *code = SSHHCurrentActivationCode();
                SSHHLog("verify tap title=%@ code=%@ action=%@",
                        title, code ?: @"(nil)", NSStringFromSelector(action));
                if (code.length > 0) {
                    SSHHUnlockWithCode(code, @"UIControl.sendAction");
                } else {
                    SSHHLog("verify tap but no code, still blocked");
                }
            }
        }
    }
    %orig;
}

%end

#pragma mark - 欢迎页

%hook TSHWelcomeViewController

// 未解锁：走原逻辑（提示输卡密）
// 已解锁：强制进主页
- (void)tsh_checkActivationAndEnterHome {
    SSHHLog("checkActivation unlocked=%d", (int)gUserUnlocked);

    if (!gUserUnlocked) {
        %orig;
        return;
    }

    SSHHWriteActivationFlags();

    if ([self respondsToSelector:@selector(tsh_didEnterHome)] && [self tsh_didEnterHome]) {
        return;
    }
    if ([self respondsToSelector:@selector(tsh_statusLabel)]) {
        UILabel *label = [self tsh_statusLabel];
        if ([label isKindOfClass:[UILabel class]]) {
            label.text = @"激活成功，正在进入…";
        }
    }
    if ([self respondsToSelector:@selector(tsh_loading)]) {
        UIActivityIndicatorView *loading = [self tsh_loading];
        if ([loading respondsToSelector:@selector(stopAnimating)]) {
            [loading stopAnimating];
        }
    }
    if ([self respondsToSelector:@selector(ToHome:)]) {
        SSHHLog("ToHome:YES");
        [self ToHome:YES];
        return;
    }
    %orig;
}

%end

#pragma mark - ctor

%ctor {
    @autoreleasepool {
        NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"(null)";
        NSString *exe = NSBundle.mainBundle.executablePath ?: @"(null)";
        SSHHLog("loaded bid=%@ exe=%@", bid, exe);

        if (!SSHHIsCalculatorProcess()) {
            SSHHLog("skip non-calculator");
            return;
        }

        if (!SSHHInstallCheckHooks()) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                SSHHInstallCheckHooks();
            });
        }

        SSHHLog("ready: type any code -> tap 验证/确定");
    }
}
