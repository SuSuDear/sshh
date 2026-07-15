//
// sshh — 任意激活码通过
//
// IDA 结论：
//   1) 欢迎页只轮询 zc_check_activation_primary/secondary (0x8C904 / 0x8C7A8)
//   2) 卡密 UI 是 banxia/wuxinglan 混淆 SDK，点确定会走网络
//   3) “不存在”来自服务端回包，不在本地字符串里
//   4) 失败路径会把 dword_1010E5600 清 0 (sub_1006C160C)
//   5) 确定按钮大概率不是标准 UIButton，只 hook UIControl 会漏
//
// 策略：
//   - 输入任意非空码后，用户再点一下（确定/空白/任意非输入区）就本地解锁
//   - primary/secondary 在解锁后恒返回 1
//   - 写本地成功 flag，并强制 ToHome
//   - 吞掉含“不存在/失败/错误”的弹窗/Toast，避免原网络回包打断
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <substrate.h>

#pragma mark - 偏移（IDA imagebase = 0x100000000）

static const uintptr_t kPrimaryCheckOff   = 0x8C904;
static const uintptr_t kSecondaryCheckOff = 0x8C7A8;
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

static BOOL gUserUnlocked = NO;
static BOOL gSlideReady = NO;
static BOOL gCheckHooksReady = NO;
static BOOL gEnterScheduled = NO;
static intptr_t gSlide = 0;
static NSString *gLastCode = nil;

typedef int (*ZCCheckFn)(void);
static ZCCheckFn orig_primary_check = NULL;
static ZCCheckFn orig_secondary_check = NULL;

#pragma mark - 基础工具

static BOOL SSHHIsCalculatorProcess(void) {
    NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSString *exe = NSBundle.mainBundle.executablePath.lastPathComponent ?: @"";
    return [bid isEqualToString:@"com.apple.calculator"] ||
           [exe isEqualToString:@"Calculator"];
}

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

// 写本地激活成功标志；失败路径可能清 0，所以进主页前会反复写
static void SSHHWriteActivationFlags(void) {
    volatile int *primaryFlag = (volatile int *)SSHHAddr(kPrimaryFlagOff);
    volatile int *secondaryFlag = (volatile int *)SSHHAddr(kSecondaryFlagOff);
    if (primaryFlag) *primaryFlag = 1;
    if (secondaryFlag) *secondaryFlag = 1;
}

#pragma mark - 校验 hook

static int hooked_primary_check(void) {
    if (gUserUnlocked) {
        SSHHWriteActivationFlags();
        return 1;
    }
    return orig_primary_check ? orig_primary_check() : 0;
}

static int hooked_secondary_check(void) {
    if (gUserUnlocked) {
        SSHHWriteActivationFlags();
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
    MSHookFunction(primary, (void *)hooked_primary_check, (void **)&orig_primary_check);
    MSHookFunction(secondary, (void *)hooked_secondary_check, (void **)&orig_secondary_check);
    gCheckHooksReady = YES;
    SSHHLog("check hooks ready p=%p s=%p", primary, secondary);
    return YES;
}

#pragma mark - 窗口 / 输入框 / 欢迎页

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

static void SSHHCollectTextFields(UIView *view, NSMutableArray<UITextField *> *outFields) {
    if (!view || view.hidden || view.alpha < 0.01) return;
    if ([view isKindOfClass:[UITextField class]]) {
        [outFields addObject:(UITextField *)view];
    }
    for (UIView *sub in view.subviews) {
        SSHHCollectTextFields(sub, outFields);
    }
}

static NSString *SSHHCurrentActivationCode(void) {
    NSMutableArray<UITextField *> *fields = [NSMutableArray array];
    for (UIWindow *w in SSHHAllWindows()) {
        // 跳过键盘窗
        NSString *cls = NSStringFromClass(w.class);
        if ([cls containsString:@"Keyboard"] || [cls containsString:@"RemoteKeyboard"]) continue;
        SSHHCollectTextFields(w, fields);
    }
    for (NSInteger i = (NSInteger)fields.count - 1; i >= 0; i--) {
        UITextField *tf = fields[i];
        NSString *text = [tf.text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (text.length > 0) return text;
    }
    if (gLastCode.length > 0) return gLastCode;
    return nil;
}

static void SSHHRememberCodeFromFields(void) {
    NSString *code = SSHHCurrentActivationCode();
    if (code.length > 0 && ![code isEqualToString:gLastCode ?: @""]) {
        gLastCode = [code copy];
        SSHHLog("code captured len=%lu", (unsigned long)code.length);
    }
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

static NSString *SSHHControlTitle(UIView *view) {
    if ([view isKindOfClass:[UIButton class]]) {
        UIButton *btn = (UIButton *)view;
        if (btn.currentTitle.length > 0) return btn.currentTitle;
        if (btn.currentAttributedTitle.string.length > 0) return btn.currentAttributedTitle.string;
    }
    if (view.accessibilityLabel.length > 0) return view.accessibilityLabel;
    for (UIView *sub in view.subviews) {
        if ([sub isKindOfClass:[UILabel class]]) {
            NSString *t = ((UILabel *)sub).text;
            if (t.length > 0) return t;
        }
    }
    return nil;
}

static BOOL SSHHIsErrorText(NSString *text) {
    if (text.length == 0) return NO;
    return [text containsString:@"不存在"] ||
           [text containsString:@"失败"] ||
           [text containsString:@"错误"] ||
           [text containsString:@"无效"] ||
           [text containsString:@"过期"] ||
           [text containsString:@"未找到"] ||
           [text containsString:@"不正确"];
}

#pragma mark - 解锁 + 进主页

static void SSHHForceEnterHome(const char *reason) {
    if (!gUserUnlocked) return;

    SSHHWriteActivationFlags();
    TSHWelcomeViewController *welcome = SSHHGetWelcomeVC();
    if (!welcome) {
        SSHHLog("enter pending, welcome nil (%s)", reason);
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

    SSHHLog("ToHome reason=%s", reason);
    if ([welcome respondsToSelector:@selector(ToHome:)]) {
        [welcome ToHome:YES];
    } else if ([welcome respondsToSelector:@selector(tsh_checkActivationAndEnterHome)]) {
        [welcome tsh_checkActivationAndEnterHome];
    }
}

// 解锁后多试几次，扛住失败路径清 flag / 异步弹窗
static void SSHHScheduleEnterHome(void) {
    if (gEnterScheduled) return;
    gEnterScheduled = YES;

    dispatch_async(dispatch_get_main_queue(), ^{
        SSHHForceEnterHome("immediate");
    });

    for (NSInteger i = 1; i <= 8; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            SSHHWriteActivationFlags();
            SSHHForceEnterHome("retry");
        });
    }
}

static void SSHHUnlockWithCode(NSString *code, NSString *reason) {
    if (code.length == 0) return;

    BOOL first = !gUserUnlocked;
    gUserUnlocked = YES;
    gLastCode = [code copy];
    SSHHWriteActivationFlags();
    SSHHLog("%s unlock code=%@ reason=%@", first ? "FIRST" : "again", code, reason);
    SSHHScheduleEnterHome();
}

// 有码就解锁：给自定义确定按钮用
static BOOL SSHHTryUnlock(NSString *reason) {
    SSHHRememberCodeFromFields();
    NSString *code = SSHHCurrentActivationCode();
    if (code.length == 0) return NO;
    SSHHUnlockWithCode(code, reason);
    return YES;
}

#pragma mark - 点击 / 触摸捕获（兼容自定义按钮）

%hook UIControl
- (void)sendAction:(SEL)action to:(id)target forEvent:(UIEvent *)event {
    if (SSHHIsCalculatorProcess()) {
        NSString *title = SSHHControlTitle(self);
        if (SSHHIsVerifyTitle(title)) {
            SSHHLog("verify control title=%@", title);
            SSHHTryUnlock(@"UIControl");
        } else {
            // 某些自定义确认控件标题为空，只要当前有码且点的是按钮就放行
            if ([self isKindOfClass:[UIButton class]] && SSHHCurrentActivationCode().length > 0) {
                SSHHLog("button tap with code, title=%@", title ?: @"(nil)");
                SSHHTryUnlock(@"UIButton.any");
            }
        }
    }
    %orig;
}
%end

%hook UITextField
- (void)endEditing:(BOOL)force {
    if (SSHHIsCalculatorProcess()) {
        NSString *text = [self.text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (text.length > 0) {
            gLastCode = [text copy];
            SSHHLog("textField endEditing code len=%lu", (unsigned long)text.length);
        }
    }
    %orig;
}

- (BOOL)resignFirstResponder {
    if (SSHHIsCalculatorProcess()) {
        NSString *text = [self.text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (text.length > 0) {
            gLastCode = [text copy];
        }
    }
    return %orig;
}
%end

// 自定义确定按钮通常不走 UIControl；用 sendEvent 抓 touch up
%hook UIApplication
- (void)sendEvent:(UIEvent *)event {
    %orig;
    if (!SSHHIsCalculatorProcess() || gUserUnlocked) return;
    if (event.type != UIEventTypeTouches) return;

    NSSet *touches = [event allTouches];
    for (UITouch *touch in touches) {
        if (touch.phase != UITouchPhaseEnded && touch.phase != UITouchPhaseCancelled) continue;

        UIView *view = touch.view;
        UIWindow *win = touch.window;
        NSString *wcls = NSStringFromClass(win.class);
        if ([wcls containsString:@"Keyboard"] || [wcls containsString:@"RemoteKeyboard"]) {
            continue; // 打字本身不触发
        }
        if ([view isKindOfClass:[UITextField class]] || [view isKindOfClass:[UITextView class]]) {
            SSHHRememberCodeFromFields();
            continue; // 点输入框只记码
        }

        // 点到非输入区：若已有非空激活码，则视为提交
        if (SSHHCurrentActivationCode().length > 0) {
            SSHHLog("touch-up unlock view=%@", NSStringFromClass(view.class));
            SSHHTryUnlock(@"touchUp");
            break;
        }
    }
}
%end

#pragma mark - 吞掉“不存在”等失败 UI

%hook UIViewController
- (void)presentViewController:(UIViewController *)vc animated:(BOOL)flag completion:(void (^)(void))completion {
    if (SSHHIsCalculatorProcess() && gUserUnlocked &&
        [vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *title = alert.title ?: @"";
        NSString *msg = alert.message ?: @"";
        if (SSHHIsErrorText(title) || SSHHIsErrorText(msg)) {
            SSHHLog("swallow alert title=%@ msg=%@", title, msg);
            SSHHForceEnterHome("alert-swallow");
            if (completion) completion();
            return;
        }
    }
    %orig;
}
%end

%hook UILabel
- (void)setText:(NSString *)text {
    if (SSHHIsCalculatorProcess() && gUserUnlocked && SSHHIsErrorText(text)) {
        SSHHLog("rewrite label error: %@", text);
        %orig(@"激活成功，正在进入…");
        SSHHForceEnterHome("label-error");
        return;
    }
    %orig;
}
%end

%hook MBProgressHUD
+ (id)wj_showError:(id)msg {
    if (SSHHIsCalculatorProcess() && (gUserUnlocked || SSHHCurrentActivationCode().length > 0)) {
        SSHHLog("swallow wj_showError: %@", msg);
        if (!gUserUnlocked) SSHHTryUnlock(@"wj_showError");
        return nil;
    }
    return %orig;
}
+ (id)wj_showError:(id)msg toView:(id)view {
    if (SSHHIsCalculatorProcess() && (gUserUnlocked || SSHHCurrentActivationCode().length > 0)) {
        SSHHLog("swallow wj_showError:toView: %@", msg);
        if (!gUserUnlocked) SSHHTryUnlock(@"wj_showError2");
        return nil;
    }
    return %orig;
}
+ (id)wj_showError:(id)msg hideAfterDelay:(NSTimeInterval)delay toView:(id)view {
    if (SSHHIsCalculatorProcess() && (gUserUnlocked || SSHHCurrentActivationCode().length > 0)) {
        SSHHLog("swallow wj_showError3: %@", msg);
        if (!gUserUnlocked) SSHHTryUnlock(@"wj_showError3");
        return nil;
    }
    return %orig;
}
+ (id)wj_showText:(id)msg view:(id)view {
    if (SSHHIsCalculatorProcess()) {
        NSString *s = [msg isKindOfClass:[NSString class]] ? (NSString *)msg : [msg description];
        if (SSHHIsErrorText(s) && SSHHCurrentActivationCode().length > 0) {
            SSHHLog("swallow wj_showText: %@", s);
            SSHHTryUnlock(@"wj_showText");
            return nil;
        }
    }
    return %orig;
}
+ (id)wj_showPlainText:(id)msg view:(id)view {
    if (SSHHIsCalculatorProcess()) {
        NSString *s = [msg isKindOfClass:[NSString class]] ? (NSString *)msg : [msg description];
        if (SSHHIsErrorText(s) && SSHHCurrentActivationCode().length > 0) {
            SSHHLog("swallow wj_showPlainText: %@", s);
            SSHHTryUnlock(@"wj_showPlainText");
            return nil;
        }
    }
    return %orig;
}
+ (id)wj_showPlainText:(id)msg hideAfterDelay:(NSTimeInterval)delay view:(id)view {
    if (SSHHIsCalculatorProcess()) {
        NSString *s = [msg isKindOfClass:[NSString class]] ? (NSString *)msg : [msg description];
        if (SSHHIsErrorText(s) && SSHHCurrentActivationCode().length > 0) {
            SSHHLog("swallow wj_showPlainText2: %@", s);
            SSHHTryUnlock(@"wj_showPlainText2");
            return nil;
        }
    }
    return %orig;
}
%end

#pragma mark - 欢迎页

%hook TSHWelcomeViewController
- (void)tsh_checkActivationAndEnterHome {
    if (!gUserUnlocked) {
        %orig; // 未输入时保持“请先输入卡密”
        return;
    }
    SSHHWriteActivationFlags();
    if ([self respondsToSelector:@selector(tsh_didEnterHome)] && [self tsh_didEnterHome]) return;
    if ([self respondsToSelector:@selector(tsh_statusLabel)]) {
        UILabel *label = [self tsh_statusLabel];
        if ([label isKindOfClass:[UILabel class]]) label.text = @"激活成功，正在进入…";
    }
    if ([self respondsToSelector:@selector(tsh_loading)]) {
        UIActivityIndicatorView *loading = [self tsh_loading];
        if ([loading respondsToSelector:@selector(stopAnimating)]) [loading stopAnimating];
    }
    if ([self respondsToSelector:@selector(ToHome:)]) {
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
        SSHHLog("ready: type any code, then tap 确定/任意非输入区");
    }
}
