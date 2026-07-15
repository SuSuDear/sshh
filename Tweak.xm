//
// sshh
// 1) 原版激活绕过：欢迎页直进主页 + 底层校验返回 1
// 2) 绘制启动诊断：记录 HUDThread/posix_spawn 结果，定位“点开启绘制就崩”
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <spawn.h>
#import <string.h>
#import <errno.h>
#import <substrate.h>

// IDA：primary @ 0x10008C904 / secondary @ 0x10008C7A8
static const uintptr_t kPrimaryCheckFileOff   = 0x8C904;
static const uintptr_t kSecondaryCheckFileOff = 0x8C7A8;
static const uintptr_t kPreferredBase         = 0x100000000ULL;

#ifndef SSHH_LOG
#define SSHH_LOG 1
#endif

#if SSHH_LOG
#define SSHHLog(fmt, ...) NSLog(@"[sshh] " fmt, ##__VA_ARGS__)
#else
#define SSHHLog(fmt, ...)
#endif

#pragma mark - 最小 ObjC 声明

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

#pragma mark - 底层激活检查 hook

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

static BOOL SSHHInstallFunctionHooks(void) {
    if (gFunctionHooksInstalled) return YES;

    const char *name = NULL;
    const struct mach_header *header = NULL;
    intptr_t slide = 0;
    if (!SSHHFindMainImage(&name, &header, &slide)) {
        SSHHLog("main image not found");
        return NO;
    }

    uintptr_t primary = kPreferredBase + kPrimaryCheckFileOff + (uintptr_t)slide;
    uintptr_t secondary = kPreferredBase + kSecondaryCheckFileOff + (uintptr_t)slide;

    SSHHLog("image=%s slide=0x%lx", name ? name : "(null)", (unsigned long)slide);
    SSHHLog("hook primary=%p secondary=%p", (void *)primary, (void *)secondary);
    SSHHLog("insn primary=0x%08x secondary=0x%08x",
            *(uint32_t *)primary, *(uint32_t *)secondary);

    MSHookFunction((void *)primary, (void *)&hooked_primary_check, (void **)&orig_primary_check);
    MSHookFunction((void *)secondary, (void *)&hooked_secondary_check, (void **)&orig_secondary_check);

    gFunctionHooksInstalled = YES;
    SSHHLog("function hooks installed");
    return YES;
}

#pragma mark - posix_spawn 诊断（绘制子进程入口）

// 原版：posix_spawn(path=self, argv=["...","start"|"Finish"|"examine"], persona=99)
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
        SSHHLog("posix_spawn OK pid=%d path=%s argv=[%@]",
                pid ? (int)*pid : -1, path ? path : "(null)", argvText);
    } else {
        SSHHLog("posix_spawn FAIL rc=%d errno=%d(%s) path=%s argv=[%@]",
                rc, errno, strerror(errno), path ? path : "(null)", argvText);
    }
    return rc;
}

static void SSHHInstallPosixSpawnHook(void) {
    // 直接 hook 符号，覆盖 StartAndEnd / CheckHudThreadState 两条路径
    MSHookFunction((void *)posix_spawn, (void *)hooked_posix_spawn, (void **)&orig_posix_spawn);
    SSHHLog("posix_spawn hook installed orig=%p", orig_posix_spawn);
}

#pragma mark - 欢迎页激活绕过

static void SSHHForceEnterHome(TSHWelcomeViewController *self, const char *reason) {
    if (!self) return;

    if ([self respondsToSelector:@selector(tsh_didEnterHome)] && [self tsh_didEnterHome]) {
        SSHHLog("enterHome skip (already home) reason=%s", reason);
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
        SSHHLog("force ToHome:YES reason=%s", reason);
        [self ToHome:YES];
        return;
    }

    SSHHLog("ToHome: missing, reason=%s", reason);
}

%hook TSHWelcomeViewController

- (void)tsh_checkActivationAndEnterHome {
    SSHHLog("tsh_checkActivationAndEnterHome hit");
    SSHHForceEnterHome(self, "checkActivation");
}

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    SSHHLog("welcome viewDidAppear animated=%d", (int)animated);

    __weak TSHWelcomeViewController *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        TSHWelcomeViewController *strongSelf = weakSelf;
        if (!strongSelf) return;
        SSHHForceEnterHome(strongSelf, "viewDidAppear");
    });
}

%end

#pragma mark - 绘制开关诊断

%hook HUDThread

// YES=start 子进程 / NO=Finish 杀进程
+ (void)StartAndEnd:(BOOL)start {
    NSString *pidPath = nil;
    NSString *statePath = nil;
    if ([objc_getClass("HUDConfig") respondsToSelector:@selector(GET_PID_PATH)]) {
        pidPath = [objc_getClass("HUDConfig") GET_PID_PATH];
    }
    if ([objc_getClass("HUDConfig") respondsToSelector:@selector(GET_STATE_PATH)]) {
        statePath = [objc_getClass("HUDConfig") GET_STATE_PATH];
    }

    SSHHLog("HUDThread StartAndEnd:%d pidPath=%@ statePath=%@ exe=%@",
            (int)start, pidPath, statePath, NSBundle.mainBundle.executablePath);

    @try {
        %orig;
        SSHHLog("HUDThread StartAndEnd:%d returned", (int)start);
    } @catch (NSException *ex) {
        SSHHLog("HUDThread StartAndEnd:%d EXCEPTION %@ reason=%@",
                (int)start, ex.name, ex.reason);
        @throw;
    }

    // 启动后短延迟检查 pid 文件 / state 文件是否生成
    if (start) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            NSFileManager *fm = NSFileManager.defaultManager;
            BOOL pidExists = pidPath ? [fm fileExistsAtPath:pidPath] : NO;
            BOOL stateExists = statePath ? [fm fileExistsAtPath:statePath] : NO;
            NSString *pidContent = pidExists ? [NSString stringWithContentsOfFile:pidPath encoding:NSUTF8StringEncoding error:nil] : nil;
            SSHHLog("HUD post-start check pidExists=%d pid=%@ stateExists=%d",
                    (int)pidExists, pidContent, (int)stateExists);
        });
    }
}

+ (BOOL)CheckHudThreadState:(NSString *)arg {
    BOOL ret = %orig;
    SSHHLog("HUDThread CheckHudThreadState:%@ -> %d", arg, (int)ret);
    return ret;
}

%end

%hook ViewController

// 主页“开启绘制”按钮
- (void)startButtonTapped {
    BOOL running = NO;
    if ([self respondsToSelector:@selector(GetRunning:)]) {
        running = [self GetRunning:@"examine"];
    }
    SSHHLog("startButtonTapped running(examine)=%d", (int)running);
    %orig;
    SSHHLog("startButtonTapped returned");
}

%end

#pragma mark - ctor

%ctor {
    @autoreleasepool {
        NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"(null)";
        NSString *exe = NSBundle.mainBundle.executablePath ?: @"(null)";
        NSArray *args = NSProcessInfo.processInfo.arguments ?: @[];
        SSHHLog("loaded bid=%@ exe=%@ args=%@ uid=%d euid=%d",
                bid, exe, args, (int)getuid(), (int)geteuid());

        BOOL isCalc = [bid isEqualToString:@"com.apple.calculator"] ||
                      [exe.lastPathComponent isEqualToString:@"Calculator"];
        if (!isCalc) {
            SSHHLog("not calculator host, keep only spawn log if injected");
        }

        // 1) 激活绕过
        if (isCalc) {
            if (!SSHHInstallFunctionHooks()) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{
                    SSHHInstallFunctionHooks();
                });
            }
        }

        // 2) 绘制 spawn 诊断（主进程 + 若子进程也注入则同样可见）
        SSHHInstallPosixSpawnHook();

        Class welcomeCls = objc_getClass("TSHWelcomeViewController");
        Class hudThreadCls = objc_getClass("HUDThread");
        Class vcCls = objc_getClass("ViewController");
        SSHHLog("classes welcome=%p HUDThread=%p ViewController=%p", welcomeCls, hudThreadCls, vcCls);
        SSHHLog("init done");
    }
}
