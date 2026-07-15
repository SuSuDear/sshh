//
// sshh
// 1) 激活绕过
// 2) 绘制 spawn 诊断
// 3) 日志窗关闭解锁 + HUD 触摸路由修复
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <spawn.h>
#import <string.h>
#import <errno.h>
#import <substrate.h>

// 底层激活校验
static const uintptr_t kPrimaryCheckFileOff   = 0x8C904;
static const uintptr_t kSecondaryCheckFileOff = 0x8C7A8;
// HID hitTest 目标窗口全局：qword_1010C5390
static const uintptr_t kHitWindowGlobalOff    = 0x10C5390;
// sub_1000302DC: 把 windows.firstObject 塞进全局
static const uintptr_t kSetHitWindowFileOff   = 0x302DC;
static const uintptr_t kPreferredBase         = 0x100000000ULL;

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

@interface HUDThread : NSObject
+ (void)StartAndEnd:(BOOL)start;
+ (BOOL)CheckHudThreadState:(NSString *)arg;
@end

@interface HUDConfig : NSObject
+ (NSString *)GET_PID_PATH;
+ (NSString *)GET_STATE_PATH;
+ (NSString *)GET_LAUNCHED;
+ (NSString *)GET_DISMISSAL;
@end

@interface ViewController : UIViewController
- (void)startButtonTapped;
- (BOOL)GetRunning:(id)arg;
@end

@interface LogViewController : UIViewController
- (BOOL)canCloseLogPanel;
- (void)setCanCloseLogPanel:(BOOL)value;
- (UIButton *)closeButton;
- (UILabel *)titleLabel;
- (UIView *)containerView;
- (UITextView *)textView;
- (void)closeTapped;
- (void)hideLogMenuAnimated:(BOOL)animated;
- (void)setLogSystemActive:(BOOL)active;
@end

@interface HUDDelegate : NSObject
- (BOOL)application:(id)app didFinishLaunchingWithOptions:(id)opts;
- (UIWindow *)logwindow;
- (UIWindow *)hudwindow;
- (UIViewController *)logRootViewController;
@end

@interface LOGRootWindow : UIWindow
@end

@interface HUDMainWindow : UIWindow
@end

#pragma mark - 环境

static BOOL SSHHIsHUDProcess(void) {
    NSArray *args = NSProcessInfo.processInfo.arguments ?: @[];
    for (NSString *a in args) {
        if ([a isEqualToString:@"start"] || [a isEqualToString:@"Finish"] || [a isEqualToString:@"examine"]) {
            return YES;
        }
    }
    // HUD 子进程通常 uid=0
    if (geteuid() == 0 && args.count >= 2) return YES;
    return NO;
}

static BOOL SSHHIsCalculatorHost(void) {
    NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSString *exe = NSBundle.mainBundle.executablePath.lastPathComponent ?: @"";
    return [bid isEqualToString:@"com.apple.calculator"] || [exe isEqualToString:@"Calculator"];
}

static BOOL SSHHFindMainImage(const char **outName, const struct mach_header **outHeader, intptr_t *outSlide) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "sshh") != NULL) continue;
        BOOL hit = NO;
        if (strstr(name, "/Calculator.app/Calculator") != NULL) hit = YES;
        if (!hit && strstr(name, "PersistenceHelper") != NULL && strstr(name, ".dylib") == NULL) hit = YES;
        if (!hit) continue;
        *outName = name;
        *outHeader = _dyld_get_image_header(i);
        *outSlide = _dyld_get_image_vmaddr_slide(i);
        return YES;
    }
    if (count > 0) {
        *outName = _dyld_get_image_name(0);
        *outHeader = _dyld_get_image_header(0);
        *outSlide = _dyld_get_image_vmaddr_slide(0);
        return (*outHeader != NULL);
    }
    return NO;
}

static intptr_t gSlide = 0;
static BOOL gSlideReady = NO;

static BOOL SSHHEnsureSlide(void) {
    if (gSlideReady) return YES;
    const char *name = NULL;
    const struct mach_header *header = NULL;
    intptr_t slide = 0;
    if (!SSHHFindMainImage(&name, &header, &slide)) return NO;
    gSlide = slide;
    gSlideReady = YES;
    SSHHLog("image=%s slide=0x%lx", name ? name : "(null)", (unsigned long)slide);
    return YES;
}

#pragma mark - 激活校验 hook

typedef int (*ZCCheckFn)(void);
static ZCCheckFn orig_primary_check = NULL;
static ZCCheckFn orig_secondary_check = NULL;
static BOOL gFunctionHooksInstalled = NO;

static int hooked_primary_check(void) {
    SSHHLog("primary check -> 1");
    return 1;
}
static int hooked_secondary_check(void) {
    SSHHLog("secondary check -> 1");
    return 1;
}

static BOOL SSHHInstallFunctionHooks(void) {
    if (gFunctionHooksInstalled) return YES;
    if (!SSHHEnsureSlide()) return NO;
    uintptr_t primary = kPreferredBase + kPrimaryCheckFileOff + (uintptr_t)gSlide;
    uintptr_t secondary = kPreferredBase + kSecondaryCheckFileOff + (uintptr_t)gSlide;
    SSHHLog("hook primary=%p secondary=%p", (void *)primary, (void *)secondary);
    MSHookFunction((void *)primary, (void *)&hooked_primary_check, (void **)&orig_primary_check);
    MSHookFunction((void *)secondary, (void *)&hooked_secondary_check, (void **)&orig_secondary_check);
    gFunctionHooksInstalled = YES;
    return YES;
}

#pragma mark - posix_spawn 诊断

static int (*orig_posix_spawn)(pid_t *pid, const char *path,
                               const posix_spawn_file_actions_t *file_actions,
                               const posix_spawnattr_t *attrp,
                               char *const argv[], char *const envp[]) = NULL;

static NSString *SSHHJoinArgv(char *const argv[]) {
    if (!argv) return @"(null argv)";
    NSMutableArray *parts = [NSMutableArray array];
    for (int i = 0; argv[i]; i++) {
        [parts addObject:[NSString stringWithUTF8String:argv[i] ?: "(null)"]];
    }
    return [parts componentsJoinedByString:@" | "];
}

static int hooked_posix_spawn(pid_t *pid, const char *path,
                              const posix_spawn_file_actions_t *file_actions,
                              const posix_spawnattr_t *attrp,
                              char *const argv[], char *const envp[]) {
    NSString *argvText = SSHHJoinArgv(argv);
    SSHHLog("posix_spawn ENTER path=%s argv=[%@] uid=%d euid=%d",
            path ? path : "(null)", argvText, (int)getuid(), (int)geteuid());
    int rc = orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    if (rc == 0) {
        SSHHLog("posix_spawn OK pid=%d argv=[%@]", pid ? (int)*pid : -1, argvText);
    } else {
        SSHHLog("posix_spawn FAIL rc=%d errno=%d(%s) argv=[%@]",
                rc, errno, strerror(errno), argvText);
    }
    return rc;
}

static void SSHHInstallPosixSpawnHook(void) {
    MSHookFunction((void *)posix_spawn, (void *)hooked_posix_spawn, (void **)&orig_posix_spawn);
    SSHHLog("posix_spawn hook installed");
}

#pragma mark - 欢迎页

static void SSHHForceEnterHome(TSHWelcomeViewController *self, const char *reason) {
    if (!self) return;
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
        SSHHLog("force ToHome reason=%s", reason);
        [self ToHome:YES];
    }
}

%hook TSHWelcomeViewController
- (void)tsh_checkActivationAndEnterHome {
    SSHHLog("tsh_checkActivationAndEnterHome hit");
    SSHHForceEnterHome(self, "checkActivation");
}
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    __weak TSHWelcomeViewController *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        SSHHForceEnterHome(weakSelf, "viewDidAppear");
    });
}
%end

#pragma mark - 绘制按钮诊断

%hook HUDThread
+ (void)StartAndEnd:(BOOL)start {
    SSHHLog("HUDThread StartAndEnd:%d euid=%d", (int)start, (int)geteuid());
    %orig;
    SSHHLog("HUDThread StartAndEnd:%d returned", (int)start);
}
+ (BOOL)CheckHudThreadState:(NSString *)arg {
    BOOL ret = %orig;
    SSHHLog("CheckHudThreadState:%@ -> %d", arg, (int)ret);
    return ret;
}
%end

%hook ViewController
- (void)startButtonTapped {
    BOOL running = [self respondsToSelector:@selector(GetRunning:)] ? [self GetRunning:@"examine"] : NO;
    SSHHLog("startButtonTapped running=%d", (int)running);
    %orig;
}
%end

#pragma mark - 日志窗关闭解锁

static void SSHHUnlockCloseButton(LogViewController *self, const char *reason) {
    if (!self) return;
    if ([self respondsToSelector:@selector(setCanCloseLogPanel:)]) {
        [self setCanCloseLogPanel:YES];
    }
    UIButton *btn = [self respondsToSelector:@selector(closeButton)] ? [self closeButton] : nil;
    if ([btn isKindOfClass:[UIButton class]]) {
        btn.enabled = YES;
        btn.userInteractionEnabled = YES;
        btn.alpha = 1.0;
    }
    UIView *container = [self respondsToSelector:@selector(containerView)] ? [self containerView] : nil;
    if (container) {
        container.userInteractionEnabled = YES;
        container.hidden = NO;
        container.alpha = 1.0;
    }
    UITextView *tv = [self respondsToSelector:@selector(textView)] ? (UITextView *)[self textView] : nil;
    if ([tv isKindOfClass:[UITextView class]]) {
        tv.userInteractionEnabled = YES;
        tv.editable = NO;
        tv.selectable = YES;
    }
    self.view.userInteractionEnabled = YES;

    if ([self respondsToSelector:@selector(titleLabel)]) {
        UILabel *title = [self titleLabel];
        if ([title isKindOfClass:[UILabel class]]) {
            NSString *cur = title.text ?: @"";
            if ([cur containsString:@"等待"] || [cur containsString:@"关闭日志"] || cur.length == 0) {
                title.text = @"日志（可随时关闭）";
            }
        }
    }
    SSHHLog("unlock close reason=%s btn=%p enabled=%d", reason, btn, (int)btn.enabled);
}

%hook LogViewController
- (BOOL)canCloseLogPanel {
    return YES;
}
- (void)setCanCloseLogPanel:(BOOL)value {
    %orig(YES);
}
- (void)viewDidLoad {
    %orig;
    SSHHUnlockCloseButton(self, "viewDidLoad");
    __weak LogViewController *weakSelf = self;
    dispatch_async(dispatch_get_main_queue(), ^{ SSHHUnlockCloseButton(weakSelf, "vdl.async"); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SSHHUnlockCloseButton(weakSelf, "vdl.0.3s");
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SSHHUnlockCloseButton(weakSelf, "vdl.1s");
    });
}
- (void)updateStatusForLogLine:(id)line {
    %orig;
    SSHHUnlockCloseButton(self, "updateStatus");
}
- (void)closeTapped {
    SSHHLog("closeTapped");
    SSHHUnlockCloseButton(self, "closeTapped");
    %orig;
}
%end

#pragma mark - HUD 触摸路由修复

// 原版 HID 回调只 hitTest windows.firstObject
// 创建顺序/层级下 firstObject 常是 HUDMainWindow（绘制窗，交互关闭）→ 触摸全丢
// 这里强制把 hitTest 目标设为 LOGRootWindow

static void (*orig_set_hit_window)(id a1) = NULL;
static BOOL gHitWindowHookInstalled = NO;

static UIWindow *SSHHFindLogWindow(void) {
    Class logCls = objc_getClass("LOGRootWindow");
    UIApplication *app = UIApplication.sharedApplication;
    // iOS 15+ windows 可能空，尽量扫
    NSArray *windows = nil;
    if ([app respondsToSelector:@selector(windows)]) {
        windows = app.windows;
    }
    for (UIWindow *w in windows) {
        if (logCls && [w isKindOfClass:logCls]) return w;
        // 兜底：rootVC 是 LogViewController
        if ([NSStringFromClass([w.rootViewController class]) isEqualToString:@"LogViewController"]) return w;
    }
    return nil;
}

static void SSHHForceHitTestWindow(const char *reason) {
    if (!SSHHEnsureSlide()) return;
    UIWindow *log = SSHHFindLogWindow();
    if (!log) {
        SSHHLog("force hit window: log not found (%s)", reason);
        return;
    }
    // 原二进制全局 slot 存 strong UIWindow*。
    // ARC 禁止把整数地址直接转成 id*，也不能裸用 objc_retain/objc_release。
    // 用 void** + CFRetain/CFRelease 写全局，语义等价于强引用替换。
    void **slot = (void **)(uintptr_t)(kPreferredBase + kHitWindowGlobalOff + (uintptr_t)gSlide);
    void *old = *slot;
    if (old == (__bridge void *)log) {
        SSHHLog("hit window already LOG (%s) %p", reason, log);
        return;
    }
    CFRetain((__bridge CFTypeRef)log);
    *slot = (__bridge void *)log;
    if (old) {
        CFRelease((CFTypeRef)old);
    }
    SSHHLog("hit window forced LOG (%s) %p old=%p", reason, log, old);
}

static void hooked_set_hit_window(id a1) {
    // 先走原逻辑，再覆盖为 log 窗
    if (orig_set_hit_window) orig_set_hit_window(a1);
    SSHHForceHitTestWindow("set_hit_window");
}

static void SSHHInstallHitWindowHook(void) {
    if (gHitWindowHookInstalled) return;
    if (!SSHHEnsureSlide()) return;
    void *fn = (void *)(kPreferredBase + kSetHitWindowFileOff + (uintptr_t)gSlide);
    MSHookFunction(fn, (void *)hooked_set_hit_window, (void **)&orig_set_hit_window);
    gHitWindowHookInstalled = YES;
    SSHHLog("hit-window hook installed fn=%p", fn);
}

static void SSHHFixHUDWindows(const char *reason) {
    UIWindow *log = SSHHFindLogWindow();
    Class hudCls = objc_getClass("HUDMainWindow");
    UIWindow *hud = nil;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (hudCls && [w isKindOfClass:hudCls]) { hud = w; break; }
    }

    // 日志窗提到最高，绘制窗可显示但不可点
    if (log) {
        // 原版 log=statusBar-1 / hud=statusBar+1，自定义 HID 又只测 firstObject，极易点穿
        log.windowLevel = 10000001.0;
        log.hidden = NO;
        log.userInteractionEnabled = YES;
        [log makeKeyAndVisible];
        if ([log.rootViewController isKindOfClass:objc_getClass("LogViewController")]) {
            SSHHUnlockCloseButton((LogViewController *)log.rootViewController, reason);
        }
    }
    if (hud) {
        hud.windowLevel = 10000000.0; // 仍可盖住游戏，但低于 log
        hud.userInteractionEnabled = NO;
        hud.rootViewController.view.userInteractionEnabled = NO;
    }

    SSHHForceHitTestWindow(reason);
    SSHHLog("fix HUD windows reason=%s log=%p level=%.1f hud=%p",
            reason, log, log.windowLevel, hud);
}

%hook HUDMainWindow
// 系统命中测试：绘制窗永不吃触摸
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    return nil;
}
- (BOOL)_ignoresHitTest {
    return YES;
}
- (BOOL)userInteractionEnabled {
    return NO;
}
%end

%hook LOGRootWindow
- (BOOL)_ignoresHitTest {
    return NO;
}
- (BOOL)userInteractionEnabled {
    return YES;
}
// 保证日志窗可点
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = %orig;
    if (!v) {
        // 兜底：点在窗口内就返回 rootView
        if (CGRectContainsPoint(self.bounds, point)) {
            return self.rootViewController.view ?: self;
        }
    }
    return v;
}
%end

%hook HUDDelegate
- (BOOL)application:(id)app didFinishLaunchingWithOptions:(id)opts {
    BOOL ret = %orig;
    SSHHLog("HUDDelegate didFinishLaunching");
    // 窗口刚建完立刻修层级/命中
    SSHHFixHUDWindows("didFinishLaunching");
    dispatch_async(dispatch_get_main_queue(), ^{ SSHHFixHUDWindows("didFinish.async"); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SSHHFixHUDWindows("didFinish.0.2s");
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SSHHFixHUDWindows("didFinish.1s");
    });
    // 利用过程中再刷几次，防止状态刷新把按钮打回 disabled
    for (int i = 2; i <= 8; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            SSHHFixHUDWindows("keepalive");
        });
    }
    return ret;
}
%end

#pragma mark - ctor

%ctor {
    @autoreleasepool {
        NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"(null)";
        NSString *exe = NSBundle.mainBundle.executablePath ?: @"(null)";
        NSArray *args = NSProcessInfo.processInfo.arguments ?: @[];
        BOOL isHUD = SSHHIsHUDProcess();
        BOOL isCalc = SSHHIsCalculatorHost();
        SSHHLog("loaded bid=%@ exe=%@ args=%@ uid=%d euid=%d hud=%d",
                bid, exe, args, (int)getuid(), (int)geteuid(), (int)isHUD);

        if (isCalc && !isHUD) {
            // 主界面：激活绕过 + spawn 诊断
            SSHHInstallFunctionHooks();
            SSHHInstallPosixSpawnHook();
        }

        if (isHUD || isCalc) {
            // HUD 子进程：触摸/关闭修复
            if (isHUD) {
                SSHHInstallHitWindowHook();
                // 延迟再装一次，防 image slide 尚未稳定
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    SSHHInstallHitWindowHook();
                    SSHHFixHUDWindows("hud.ctor");
                });
            }
        }

        SSHHLog("classes LogVC=%p HUDDelegate=%p LOGRoot=%p HUDMain=%p",
                objc_getClass("LogViewController"),
                objc_getClass("HUDDelegate"),
                objc_getClass("LOGRootWindow"),
                objc_getClass("HUDMainWindow"));
        SSHHLog("init done v0.1.4");
    }
}
