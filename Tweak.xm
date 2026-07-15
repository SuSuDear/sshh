//
// sshh
// 1) 激活绕过
// 2) 绘制 spawn 诊断
// 3) 日志窗关闭解锁 + HUD 触摸路由修复
//
// v0.1.5 关键修复：
// 原版 HIDDeliverTouchOnMain 每次触摸都对全局 hit 窗口 hitTest，
// 该全局只在 once 里写成 windows.firstObject（常为 HUDMainWindow）。
// 仅 hook set_hit_window 不够稳：once 时序/晚注入/旧值残留都会失败。
// 现在在每次 deliver touch 入口强制把全局改成 LOGRootWindow。
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
// sub_1000302DC: 把 windows.firstObject 塞进全局（once 回调）
static const uintptr_t kSetHitWindowFileOff   = 0x302DC;
// sub_100030134: HID 主线程投递触摸，每次触摸都会走这里
static const uintptr_t kDeliverTouchFileOff   = 0x30134;
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
        btn.hidden = NO;
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
        tv.scrollEnabled = YES;
    }
    self.view.userInteractionEnabled = YES;
    self.view.hidden = NO;

    if ([self respondsToSelector:@selector(titleLabel)]) {
        UILabel *title = [self titleLabel];
        if ([title isKindOfClass:[UILabel class]]) {
            NSString *cur = title.text ?: @"";
            if ([cur containsString:@"等待"] || [cur containsString:@"关闭日志"] || cur.length == 0) {
                title.text = @"日志（可随时关闭）";
            }
        }
    }
    SSHHLog("unlock close reason=%s btn=%p enabled=%d alpha=%.2f",
            reason, btn, (int)btn.enabled, btn ? btn.alpha : -1.0);
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
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    SSHHUnlockCloseButton(self, "viewDidAppear");
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

// 原版链路：
// BKSHIDEventRegisterEventCallback -> HIDDeliverTouchOnMain
//   OnceInitHitTestWindow -> SetHitTestWindowFromFirstObject
//   view = [qword_1010C5390 hitTest:point withEvent:nil]
//   [TSEventFetcher ... inWindow:qword_1010C5390 onView:view]
//
// firstObject 高概率是 HUDMainWindow（level 更高且 _ignoresHitTest=YES）
// → 日志/关闭按钮永远收不到合成触摸

static void (*orig_set_hit_window)(id a1) = NULL;
static void (*orig_deliver_touch)(void *ctx) = NULL;
static BOOL gHitWindowHookInstalled = NO;
static BOOL gDeliverTouchHookInstalled = NO;
static NSUInteger gDeliverTouchCount = 0;
static NSUInteger gForceLogCount = 0;

static UIWindow *SSHHFindHUDWindow(void) {
    Class hudCls = objc_getClass("HUDMainWindow");
    id del = UIApplication.sharedApplication.delegate;
    if ([del respondsToSelector:@selector(hudwindow)]) {
        UIWindow *w = [del hudwindow];
        if (w) return w;
    }
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (hudCls && [w isKindOfClass:hudCls]) return w;
        if ([NSStringFromClass(w.class) isEqualToString:@"HUDMainWindow"]) return w;
    }
    return nil;
}

static UIWindow *SSHHFindLogWindow(void) {
    Class logCls = objc_getClass("LOGRootWindow");

    // 1) 优先走 HUDDelegate 持有的强引用，不依赖 windows 顺序
    id del = UIApplication.sharedApplication.delegate;
    if ([del respondsToSelector:@selector(logwindow)]) {
        UIWindow *w = [del logwindow];
        if (w) return w;
    }

    UIApplication *app = UIApplication.sharedApplication;
    NSArray *windows = nil;
    if ([app respondsToSelector:@selector(windows)]) {
        windows = app.windows;
    }
    for (UIWindow *w in windows) {
        if (logCls && [w isKindOfClass:logCls]) return w;
        if ([NSStringFromClass(w.class) isEqualToString:@"LOGRootWindow"]) return w;
        // 兜底：rootVC 是 LogViewController
        if ([NSStringFromClass([w.rootViewController class]) isEqualToString:@"LogViewController"]) return w;
    }
    return nil;
}

// 读取当前全局 hit 窗口指针（不 retain）
static UIWindow *SSHHGetGlobalHitWindow(void) {
    if (!SSHHEnsureSlide()) return nil;
    void **slot = (void **)(uintptr_t)(kPreferredBase + kHitWindowGlobalOff + (uintptr_t)gSlide);
    void *cur = *slot;
    if (!cur) return nil;
    return (__bridge UIWindow *)cur;
}

// 把 LOGRootWindow 强行写入全局 hit 槽位
// 注意：原二进制对该槽位按 strong 语义持有，必须 CFRetain/CFRelease 配对
static BOOL SSHHForceHitTestWindow(const char *reason, BOOL verbose) {
    if (!SSHHEnsureSlide()) return NO;
    UIWindow *log = SSHHFindLogWindow();
    if (!log) {
        if (verbose) SSHHLog("force hit window: log not found (%s)", reason);
        return NO;
    }

    void **slot = (void **)(uintptr_t)(kPreferredBase + kHitWindowGlobalOff + (uintptr_t)gSlide);
    void *old = *slot;
    if (old == (__bridge void *)log) {
        if (verbose) {
            SSHHLog("hit window already LOG (%s) %p class=%@",
                    reason, log, NSStringFromClass(log.class));
        }
        return YES;
    }

    CFRetain((__bridge CFTypeRef)log);
    *slot = (__bridge void *)log;
    if (old) {
        CFRelease((CFTypeRef)old);
    }
    gForceLogCount++;
    if (verbose || (gForceLogCount <= 8) || ((gForceLogCount % 120) == 0)) {
        SSHHLog("hit window forced LOG (%s) %p old=%p class=%@ count=%lu",
                reason, log, old, NSStringFromClass(log.class),
                (unsigned long)gForceLogCount);
    }
    return YES;
}

static void hooked_set_hit_window(id a1) {
    // 先走原逻辑（写 firstObject），再覆盖为 log 窗
    if (orig_set_hit_window) orig_set_hit_window(a1);
    SSHHForceHitTestWindow("set_hit_window", YES);
}

// 每次触摸投递前强制全局窗口 = LOGRootWindow
// 这是修复点不了的核心：比 only-once 的 set_hit_window 更稳
static void hooked_deliver_touch(void *ctx) {
    gDeliverTouchCount++;

    UIWindow *before = SSHHGetGlobalHitWindow();
    BOOL forced = SSHHForceHitTestWindow("deliver_touch", NO);
    UIWindow *after = SSHHGetGlobalHitWindow();

    // 低频诊断，避免刷爆日志
    BOOL shouldLog = (gDeliverTouchCount <= 12) || ((gDeliverTouchCount % 180) == 0);
    if (shouldLog) {
        NSString *bcls = before ? NSStringFromClass(before.class) : @"(null)";
        NSString *acls = after ? NSStringFromClass(after.class) : @"(null)";
        SSHHLog("deliver_touch #%lu forced=%d before=%@ after=%@ logFound=%d",
                (unsigned long)gDeliverTouchCount,
                (int)forced, bcls, acls, (int)(SSHHFindLogWindow() != nil));
    }

    if (orig_deliver_touch) {
        orig_deliver_touch(ctx);
    }
}

static void SSHHInstallHitWindowHook(void) {
    if (gHitWindowHookInstalled) return;
    if (!SSHHEnsureSlide()) return;
    void *fn = (void *)(kPreferredBase + kSetHitWindowFileOff + (uintptr_t)gSlide);
    MSHookFunction(fn, (void *)hooked_set_hit_window, (void **)&orig_set_hit_window);
    gHitWindowHookInstalled = YES;
    SSHHLog("hit-window hook installed fn=%p", fn);
}

static void SSHHInstallDeliverTouchHook(void) {
    if (gDeliverTouchHookInstalled) return;
    if (!SSHHEnsureSlide()) return;
    void *fn = (void *)(kPreferredBase + kDeliverTouchFileOff + (uintptr_t)gSlide);
    MSHookFunction(fn, (void *)hooked_deliver_touch, (void **)&orig_deliver_touch);
    gDeliverTouchHookInstalled = YES;
    SSHHLog("deliver-touch hook installed fn=%p off=0x%lx", fn, (unsigned long)kDeliverTouchFileOff);
}

static void SSHHFixHUDWindows(const char *reason) {
    UIWindow *log = SSHHFindLogWindow();
    UIWindow *hud = SSHHFindHUDWindow();

    // 日志窗提到最高；绘制窗可显示但不可点
    if (log) {
        // 原版 log=statusBar-1 / hud=statusBar+1，自定义 HID 又只测 firstObject
        log.windowLevel = 10000001.0;
        log.hidden = NO;
        log.alpha = 1.0;
        log.userInteractionEnabled = YES;
        // 不频繁 makeKeyAndVisible，避免抢焦点；首次/显式修复时再 key
        static BOOL sDidMakeKey = NO;
        if (!sDidMakeKey || [@(reason) containsString:@"didFinish"] || [@(reason) containsString:@"ctor"]) {
            [log makeKeyAndVisible];
            sDidMakeKey = YES;
        }
        if ([log.rootViewController isKindOfClass:objc_getClass("LogViewController")]) {
            SSHHUnlockCloseButton((LogViewController *)log.rootViewController, reason);
        } else if ([NSStringFromClass(log.rootViewController.class) isEqualToString:@"LogViewController"]) {
            SSHHUnlockCloseButton((LogViewController *)log.rootViewController, reason);
        }
    }
    if (hud) {
        hud.windowLevel = 10000000.0; // 仍可盖住游戏，但低于 log
        hud.userInteractionEnabled = NO;
        if (hud.rootViewController.view) {
            hud.rootViewController.view.userInteractionEnabled = NO;
        }
    }

    SSHHForceHitTestWindow(reason, YES);
    SSHHLog("fix HUD windows reason=%s log=%p level=%.1f hud=%p hudLevel=%.1f",
            reason, log, log ? log.windowLevel : -1.0, hud, hud ? hud.windowLevel : -1.0);
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
- (void)setUserInteractionEnabled:(BOOL)enabled {
    %orig(NO);
}
%end

%hook LOGRootWindow
- (BOOL)_ignoresHitTest {
    return NO;
}
- (BOOL)userInteractionEnabled {
    return YES;
}
- (void)setUserInteractionEnabled:(BOOL)enabled {
    %orig(YES);
}
// 保证日志窗可点
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = %orig;
    if (!v) {
        // 兜底：点在窗口内就尽量返回可交互子树
        if (CGRectContainsPoint(self.bounds, point)) {
            UIView *root = self.rootViewController.view;
            if (root) {
                CGPoint rp = [self convertPoint:point toView:root];
                UIView *inner = [root hitTest:rp withEvent:event];
                if (inner) return inner;
                return root;
            }
            return self;
        }
    }
    return v;
}
%end

// 合成触摸入口再兜一层：即便全局窗口写错，也把 inWindow/onView 纠到 LOG
%hook TSEventFetcher
// 返回值在原二进制里是 BOOL 语义（非 id），这里用 BOOL 避免 ARC 误处理
+ (BOOL)receiveAXEventID:(unsigned int)eventID
  atGlobalCoordinate:(CGPoint)point
      withTouchPhase:(NSInteger)phase
            inWindow:(UIWindow *)window
              onView:(UIView *)view {
    UIWindow *log = SSHHFindLogWindow();
    if (log) {
        // 窗口不对时重定向
        BOOL windowBad = (!window) || (window != log) || [window isKindOfClass:objc_getClass("HUDMainWindow")];
        if (windowBad) {
            window = log;
        }
        // view 为空或属于 HUD 时，在 LOG 上重 hitTest
        BOOL viewBad = (!view);
        if (!viewBad && view.window && view.window != log) viewBad = YES;
        if (!viewBad && [view.window isKindOfClass:objc_getClass("HUDMainWindow")]) viewBad = YES;
        if (viewBad) {
            CGPoint local = [log convertPoint:point fromWindow:nil];
            // 全局坐标 -> 窗口坐标；若 fromWindow:nil 行为异常，再试 bounds 映射
            UIView *hit = [log hitTest:local withEvent:nil];
            if (!hit) {
                // 有些机型 location 已是窗口坐标
                hit = [log hitTest:point withEvent:nil];
            }
            if (!hit) {
                hit = log.rootViewController.view ?: log;
            }
            view = hit;
            static NSUInteger sRedirectCount = 0;
            sRedirectCount++;
            if (sRedirectCount <= 12 || (sRedirectCount % 180) == 0) {
                SSHHLog("TSEventFetcher redirect #%lu phase=%ld win=%@ view=%@ pt=(%.1f,%.1f)",
                        (unsigned long)sRedirectCount,
                        (long)phase,
                        NSStringFromClass(window.class),
                        NSStringFromClass(view.class),
                        point.x, point.y);
            }
        }
    }
    return %orig(eventID, point, phase, window, view);
}
%end

%hook HUDDelegate
- (BOOL)application:(id)app didFinishLaunchingWithOptions:(id)opts {
    BOOL ret = %orig;
    SSHHLog("HUDDelegate didFinishLaunching");
    // 窗口刚建完立刻修层级/命中
    SSHHInstallHitWindowHook();
    SSHHInstallDeliverTouchHook();
    SSHHFixHUDWindows("didFinishLaunching");
    dispatch_async(dispatch_get_main_queue(), ^{ SSHHFixHUDWindows("didFinish.async"); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SSHHFixHUDWindows("didFinish.0.2s");
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SSHHFixHUDWindows("didFinish.1s");
    });
    // 利用过程中再刷几次，防止状态刷新把按钮打回 disabled
    for (int i = 2; i <= 10; i++) {
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
        SSHHLog("loaded bid=%@ exe=%@ args=%@ uid=%d euid=%d hud=%d calc=%d",
                bid, exe, args, (int)getuid(), (int)geteuid(), (int)isHUD, (int)isCalc);

        if (isCalc && !isHUD) {
            // 主界面：激活绕过 + spawn 诊断
            SSHHInstallFunctionHooks();
            SSHHInstallPosixSpawnHook();
        }

        if (isHUD) {
            // HUD 子进程：触摸/关闭修复
            // 1) once 写 firstObject 时覆盖
            // 2) 每次 deliver touch 再强制覆盖（核心）
            SSHHInstallHitWindowHook();
            SSHHInstallDeliverTouchHook();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                SSHHInstallHitWindowHook();
                SSHHInstallDeliverTouchHook();
                SSHHFixHUDWindows("hud.ctor.0.05s");
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                SSHHInstallDeliverTouchHook();
                SSHHFixHUDWindows("hud.ctor.0.5s");
            });
        }

        SSHHLog("classes LogVC=%p HUDDelegate=%p LOGRoot=%p HUDMain=%p TSEventFetcher=%p",
                objc_getClass("LogViewController"),
                objc_getClass("HUDDelegate"),
                objc_getClass("LOGRootWindow"),
                objc_getClass("HUDMainWindow"),
                objc_getClass("TSEventFetcher"));
        SSHHLog("init done v0.1.5 deliverTouch=0x%lx hitWindowGlobal=0x%lx",
                (unsigned long)kDeliverTouchFileOff,
                (unsigned long)kHitWindowGlobalOff);
    }
}
