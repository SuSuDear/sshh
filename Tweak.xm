//
// sshh
// 1) 激活绕过
// 2) 绘制 spawn 诊断
// 3) 日志窗关闭解锁 + HUD 触摸诊断/修复
//
// v0.1.6
// 截图已证明：
// - 插件在 HUD 进程生效（标题被改成“日志（可随时关闭）”）
// - 原版在“漏洞加载完成”后会自己 setCanCloseLogPanel:YES
// 所以“点不了”主因不再是 close 锁。
//
// 0.1.5 的问题：
// - 把 windowLevel 改到 1e7 且不重新 registerWindowWithContextID
//   会和 SBSAccessibilityWindowHostingController 登记的 level 脱节
// - TSEventFetcher 参数重写有调用约定风险
// - hitTest 兜底可能返回不适合 UIControl 的 view
//
// 0.1.6 策略：
// - 不再改 windowLevel / 不再乱 makeKeyAndVisible
// - 每次 HIDDeliverTouchOnMain 仍强制全局 hit 窗 = LOGRootWindow
// - 修复 HideView(secureHostView) 内部可点性
// - 写文件诊断 /var/mobile/Library/Caches/sshh-touch.log
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <spawn.h>
#import <string.h>
#import <errno.h>
#import <stdio.h>
#import <substrate.h>

// 底层激活校验
static const uintptr_t kPrimaryCheckFileOff   = 0x8C904;
static const uintptr_t kSecondaryCheckFileOff = 0x8C7A8;
// HID hitTest 目标窗口全局：qword_1010C5390
static const uintptr_t kHitWindowGlobalOff    = 0x10C5390;
// sub_1000302DC: 把 windows.firstObject 塞进全局（once 回调）
static const uintptr_t kSetHitWindowFileOff   = 0x302DC;
// sub_100030134: HID 主线程投递触摸
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
- (UIView *)secureHostView;
- (void)closeTapped;
- (void)hideLogMenuAnimated:(BOOL)animated;
- (void)setLogSystemActive:(BOOL)active;
@end

@interface HUDDelegate : NSObject
- (BOOL)application:(id)app didFinishLaunchingWithOptions:(id)opts;
- (UIWindow *)logwindow;
- (UIWindow *)hudwindow;
- (void)registerWindow:(UIWindow *)window withController:(id)controller;
@end

@interface LOGRootWindow : UIWindow
@end

@interface HUDMainWindow : UIWindow
@end

@interface HideView : UIView
- (UITextField *)textField;
- (UIView *)clearView;
- (void)refreshLiveMode;
@end

#pragma mark - 文件诊断

static void SSHHFileLog(NSString *fmt, ...) {
    static NSString *path;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        path = @"/var/mobile/Library/Caches/sshh-touch.log";
    });
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                      [NSDate date], msg];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        return;
    }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    } @catch (__unused NSException *e) {}
    [fh closeFile];
    SSHHLog("%@", msg);
}

#pragma mark - 环境

static BOOL SSHHIsHUDProcess(void) {
    NSArray *args = NSProcessInfo.processInfo.arguments ?: @[];
    for (NSString *a in args) {
        if ([a isEqualToString:@"start"] || [a isEqualToString:@"Finish"] || [a isEqualToString:@"examine"]) {
            return YES;
        }
    }
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
    SSHHFileLog(@"image=%s slide=0x%lx", name ? name : "(null)", (unsigned long)slide);
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

#pragma mark - 日志窗关闭解锁（保留，但不再乱改标题）

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
        // 确保 control event 还在
        [btn removeTarget:self action:@selector(closeTapped) forControlEvents:UIControlEventTouchUpInside];
        [btn addTarget:self action:@selector(closeTapped) forControlEvents:UIControlEventTouchUpInside];
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

    SSHHFileLog(@"unlock close reason=%s btn=%p enabled=%d alpha=%.2f containerIE=%d",
                reason, btn, (int)btn.enabled, btn ? btn.alpha : -1.0,
                container ? (int)container.userInteractionEnabled : -1);
}

// 修复 HideView 安全文本框容器：clearView 必须在可交互的内部 subview 上
static void SSHHFixSecureHost(LogViewController *self, const char *reason) {
    if (![self respondsToSelector:@selector(secureHostView)]) return;
    UIView *host = [self secureHostView];
    if (!host) return;

    host.userInteractionEnabled = YES;
    host.hidden = NO;
    host.alpha = 1.0;

    UITextField *tf = nil;
    if ([host respondsToSelector:@selector(textField)]) {
        tf = ((HideView *)host).textField;
    }
    if (![tf isKindOfClass:[UITextField class]]) {
        // 兜底扫子视图
        for (UIView *v in host.subviews) {
            if ([v isKindOfClass:[UITextField class]]) { tf = (UITextField *)v; break; }
        }
    }
    if (tf) {
        tf.userInteractionEnabled = YES;
        // 不强制改 secureTextEntry：那是“过直播”功能
        UIView *inner = tf.subviews.firstObject;
        if (inner) {
            inner.userInteractionEnabled = YES;
            UIView *clear = nil;
            if ([host respondsToSelector:@selector(clearView)]) {
                clear = ((HideView *)host).clearView;
            }
            if (clear) {
                clear.userInteractionEnabled = YES;
                clear.frame = host.bounds;
                if (clear.superview != inner) {
                    [inner addSubview:clear];
                }
                // container 若跑丢，塞回 clearView
                UIView *container = [self respondsToSelector:@selector(containerView)] ? [self containerView] : nil;
                if (container && container.superview != clear && container.superview != host) {
                    [clear addSubview:container];
                    SSHHFileLog(@"reattach container into clearView reason=%s", reason);
                }
            }
        }
        [tf setNeedsLayout];
        [tf layoutIfNeeded];
    }
    [host setNeedsLayout];
    [host layoutIfNeeded];
    SSHHFileLog(@"fix secureHost reason=%s host=%@ tf=%@ sub0=%@",
                reason, NSStringFromClass(host.class),
                tf ? NSStringFromClass(tf.class) : @"(nil)",
                tf.subviews.firstObject ? NSStringFromClass(tf.subviews.firstObject.class) : @"(nil)");
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
    SSHHFixSecureHost(self, "viewDidLoad");
    __weak LogViewController *weakSelf = self;
    dispatch_async(dispatch_get_main_queue(), ^{
        SSHHUnlockCloseButton(weakSelf, "vdl.async");
        SSHHFixSecureHost(weakSelf, "vdl.async");
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        SSHHUnlockCloseButton(weakSelf, "vdl.0.5s");
        SSHHFixSecureHost(weakSelf, "vdl.0.5s");
    });
}
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    SSHHUnlockCloseButton(self, "viewDidAppear");
    SSHHFixSecureHost(self, "viewDidAppear");
}
- (void)viewDidLayoutSubviews {
    %orig;
    SSHHFixSecureHost(self, "layout");
}
- (void)updateStatusForLogLine:(id)line {
    %orig;
    SSHHUnlockCloseButton(self, "updateStatus");
}
- (void)closeTapped {
    SSHHFileLog(@"closeTapped ENTER canClose=%d", (int)[self canCloseLogPanel]);
    SSHHUnlockCloseButton(self, "closeTapped");
    %orig;
    SSHHFileLog(@"closeTapped EXIT");
}
%end

#pragma mark - HUD 触摸路由修复（收敛版）

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
    id del = UIApplication.sharedApplication.delegate;
    if ([del respondsToSelector:@selector(logwindow)]) {
        UIWindow *w = [del logwindow];
        if (w) return w;
    }
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (logCls && [w isKindOfClass:logCls]) return w;
        if ([NSStringFromClass(w.class) isEqualToString:@"LOGRootWindow"]) return w;
        if ([NSStringFromClass([w.rootViewController class]) isEqualToString:@"LogViewController"]) return w;
    }
    return nil;
}

static UIWindow *SSHHGetGlobalHitWindow(void) {
    if (!SSHHEnsureSlide()) return nil;
    void **slot = (void **)(uintptr_t)(kPreferredBase + kHitWindowGlobalOff + (uintptr_t)gSlide);
    void *cur = *slot;
    if (!cur) return nil;
    return (__bridge UIWindow *)cur;
}

static BOOL SSHHForceHitTestWindow(const char *reason, BOOL verbose) {
    if (!SSHHEnsureSlide()) return NO;
    UIWindow *log = SSHHFindLogWindow();
    if (!log) {
        if (verbose) SSHHFileLog(@"force hit window: log not found (%s)", reason);
        return NO;
    }

    // 只保证可交互，不改 level（避免和 accessibility hosting 脱节）
    log.hidden = NO;
    log.alpha = 1.0;
    log.userInteractionEnabled = YES;

    void **slot = (void **)(uintptr_t)(kPreferredBase + kHitWindowGlobalOff + (uintptr_t)gSlide);
    void *old = *slot;
    if (old == (__bridge void *)log) {
        if (verbose) {
            SSHHFileLog(@"hit window already LOG (%s) %p class=%@ level=%.1f",
                        reason, log, NSStringFromClass(log.class), log.windowLevel);
        }
        return YES;
    }

    CFRetain((__bridge CFTypeRef)log);
    *slot = (__bridge void *)log;
    if (old) CFRelease((CFTypeRef)old);
    gForceLogCount++;
    SSHHFileLog(@"hit window forced LOG (%s) %p old=%p class=%@ level=%.1f count=%lu",
                reason, log, old, NSStringFromClass(log.class), log.windowLevel,
                (unsigned long)gForceLogCount);
    return YES;
}

static void hooked_set_hit_window(id a1) {
    if (orig_set_hit_window) orig_set_hit_window(a1);
    SSHHForceHitTestWindow("set_hit_window", YES);
}

// ctx 布局来自 IDA：+0x20 是 touch 对象，有 location / isTouchDown 等
static void hooked_deliver_touch(void *ctx) {
    gDeliverTouchCount++;
    UIWindow *before = SSHHGetGlobalHitWindow();
    BOOL forced = SSHHForceHitTestWindow("deliver_touch", NO);
    UIWindow *after = SSHHGetGlobalHitWindow();

    // 低频诊断：记录 hitTest 目标
    BOOL shouldLog = (gDeliverTouchCount <= 15) || ((gDeliverTouchCount % 120) == 0);
    if (shouldLog) {
        NSString *hitCls = @"(nil)";
        CGPoint pt = CGPointZero;
        id touchObj = nil;
        if (ctx) {
            touchObj = *(__unsafe_unretained id *)((uintptr_t)ctx + 0x20);
        }
        if (touchObj && [touchObj respondsToSelector:@selector(location)]) {
            // location 返回 CGPoint，用 objc_msgSend 取
            CGPoint (*locMsg)(id, SEL) = (CGPoint (*)(id, SEL))objc_msgSend;
            pt = locMsg(touchObj, sel_registerName("location"));
        }
        if (after) {
            UIView *hit = [after hitTest:pt withEvent:nil];
            hitCls = hit ? NSStringFromClass(hit.class) : @"(nil-hit)";
        }
        SSHHFileLog(@"deliver_touch #%lu forced=%d before=%@ after=%@ pt=(%.1f,%.1f) hit=%@ logFound=%d windows=%lu",
                    (unsigned long)gDeliverTouchCount,
                    (int)forced,
                    before ? NSStringFromClass(before.class) : @"(null)",
                    after ? NSStringFromClass(after.class) : @"(null)",
                    pt.x, pt.y, hitCls,
                    (int)(SSHHFindLogWindow() != nil),
                    (unsigned long)UIApplication.sharedApplication.windows.count);
    }

    if (orig_deliver_touch) orig_deliver_touch(ctx);
}

static void SSHHInstallHitWindowHook(void) {
    if (gHitWindowHookInstalled) return;
    if (!SSHHEnsureSlide()) return;
    void *fn = (void *)(kPreferredBase + kSetHitWindowFileOff + (uintptr_t)gSlide);
    MSHookFunction(fn, (void *)hooked_set_hit_window, (void **)&orig_set_hit_window);
    gHitWindowHookInstalled = YES;
    SSHHFileLog(@"hit-window hook installed fn=%p", fn);
}

static void SSHHInstallDeliverTouchHook(void) {
    if (gDeliverTouchHookInstalled) return;
    if (!SSHHEnsureSlide()) return;
    void *fn = (void *)(kPreferredBase + kDeliverTouchFileOff + (uintptr_t)gSlide);
    MSHookFunction(fn, (void *)hooked_deliver_touch, (void **)&orig_deliver_touch);
    gDeliverTouchHookInstalled = YES;
    SSHHFileLog(@"deliver-touch hook installed fn=%p off=0x%lx", fn, (unsigned long)kDeliverTouchFileOff);
}

// 重新把窗口登记到 SpringBoard accessibility hosting（保持原 level）
static void SSHHReregisterWindows(const char *reason) {
    UIWindow *log = SSHHFindLogWindow();
    UIWindow *hud = SSHHFindHUDWindow();
    id del = UIApplication.sharedApplication.delegate;
    if (![del respondsToSelector:@selector(registerWindow:withController:)]) {
        SSHHFileLog(@"reregister skip: no registerWindow (%s)", reason);
        return;
    }
    Class hostCls = objc_getClass("SBSAccessibilityWindowHostingController");
    if (!hostCls) {
        SSHHFileLog(@"reregister skip: no SBSAccessibilityWindowHostingController (%s)", reason);
        return;
    }
    id host = [[hostCls alloc] init];
    if (log) {
        log.userInteractionEnabled = YES;
        log.hidden = NO;
        ((void (*)(id, SEL, id, id))objc_msgSend)(del, @selector(registerWindow:withController:), log, host);
    }
    if (hud) {
        // 绘制窗保持不可点
        hud.userInteractionEnabled = NO;
        if (hud.rootViewController.view) hud.rootViewController.view.userInteractionEnabled = NO;
        ((void (*)(id, SEL, id, id))objc_msgSend)(del, @selector(registerWindow:withController:), hud, host);
    }
    SSHHFileLog(@"reregister done (%s) log=%p level=%.1f hud=%p level=%.1f",
                reason, log, log ? log.windowLevel : -1.0, hud, hud ? hud.windowLevel : -1.0);
}

static void SSHHFixHUDWindows(const char *reason) {
    UIWindow *log = SSHHFindLogWindow();
    UIWindow *hud = SSHHFindHUDWindow();

    // 关键：不改 windowLevel，只修可点性和 hit 全局
    if (log) {
        log.hidden = NO;
        log.alpha = 1.0;
        log.userInteractionEnabled = YES;
        UIViewController *rvc = log.rootViewController;
        if ([rvc isKindOfClass:objc_getClass("LogViewController")] ||
            [NSStringFromClass(rvc.class) isEqualToString:@"LogViewController"]) {
            SSHHUnlockCloseButton((LogViewController *)rvc, reason);
            SSHHFixSecureHost((LogViewController *)rvc, reason);
        }
    }
    if (hud) {
        hud.userInteractionEnabled = NO;
        if (hud.rootViewController.view) {
            hud.rootViewController.view.userInteractionEnabled = NO;
        }
    }

    SSHHForceHitTestWindow(reason, YES);
    SSHHFileLog(@"fix HUD windows reason=%s log=%p logLevel=%.1f hud=%p hudLevel=%.1f",
                reason, log, log ? log.windowLevel : -1.0, hud, hud ? hud.windowLevel : -1.0);
}

// 不再 hook hitTest 返回值，避免破坏 UIControl/手势链
%hook HUDMainWindow
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
%end

// 诊断：系统/合成事件是否真的进了 UIApplication
%hook HUDApplication
- (void)sendEvent:(UIEvent *)event {
    static NSUInteger sCnt = 0;
    sCnt++;
    if (sCnt <= 20 || (sCnt % 200) == 0) {
        NSSet *touches = [event allTouches];
        UITouch *t = touches.anyObject;
        UIView *v = t.view;
        SSHHFileLog(@"HUDApplication sendEvent #%lu type=%ld touches=%lu phase=%ld view=%@ win=%@",
                    (unsigned long)sCnt,
                    (long)event.type,
                    (unsigned long)touches.count,
                    t ? (long)t.phase : -1,
                    v ? NSStringFromClass(v.class) : @"(nil)",
                    t.window ? NSStringFromClass(t.window.class) : @"(nil)");
    }
    %orig;
}
%end

%hook HUDDelegate
- (BOOL)application:(id)app didFinishLaunchingWithOptions:(id)opts {
    BOOL ret = %orig;
    SSHHFileLog(@"HUDDelegate didFinishLaunching");
    SSHHInstallHitWindowHook();
    SSHHInstallDeliverTouchHook();
    SSHHFixHUDWindows("didFinishLaunching");
    // 用原 level 再登记一次，防止某些机型第一次 register 失败
    SSHHReregisterWindows("didFinishLaunching");
    dispatch_async(dispatch_get_main_queue(), ^{
        SSHHFixHUDWindows("didFinish.async");
        SSHHReregisterWindows("didFinish.async");
    });
    for (int i = 1; i <= 6; i++) {
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
        SSHHFileLog(@"loaded bid=%@ exe=%@ args=%@ uid=%d euid=%d hud=%d calc=%d v=0.1.6",
                    bid, exe, args, (int)getuid(), (int)geteuid(), (int)isHUD, (int)isCalc);

        if (isCalc && !isHUD) {
            SSHHInstallFunctionHooks();
            SSHHInstallPosixSpawnHook();
        }

        if (isHUD) {
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
                SSHHReregisterWindows("hud.ctor.0.5s");
            });
        }

        SSHHFileLog(@"classes LogVC=%p HUDDelegate=%p LOGRoot=%p HUDMain=%p HideView=%p HUDApp=%p",
                    objc_getClass("LogViewController"),
                    objc_getClass("HUDDelegate"),
                    objc_getClass("LOGRootWindow"),
                    objc_getClass("HUDMainWindow"),
                    objc_getClass("HideView"),
                    objc_getClass("HUDApplication"));
    }
}
