//
// sshh
// 原版 Calculator / ZeroCore PersistenceHelper 运行时激活绕过
// 策略：
//   1) Hook ObjC 流程，直接 ToHome:（主路径，不依赖卡密/网络）
//   2) Hook 底层校验函数强制返回 1（兜底，IDA: 0x8C904 / 0x8C7A8）
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <substrate.h>

// IDA 文件偏移（imagebase = 0x100000000）
// primary   @ 0x10008C904
// secondary @ 0x10008C7A8
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
- (void)setTsh_didEnterHome:(BOOL)value;
- (BOOL)tsh_activationStarted;
- (void)setTsh_activationStarted:(BOOL)value;
- (void)tsh_checkActivationAndEnterHome;
- (void)ToHome:(BOOL)animated;
- (UILabel *)tsh_statusLabel;
- (UIActivityIndicatorView *)tsh_loading;
@end

#pragma mark - 底层校验 hook（返回 1 = 已激活）

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

// 定位主可执行文件（Calculator）
static BOOL SSHHFindMainImage(const char **outName, const struct mach_header **outHeader, intptr_t *outSlide) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "sshh") != NULL) continue;

        BOOL hit = NO;
        // 主路径：Calculator.app/Calculator
        if (strstr(name, "/Calculator.app/Calculator") != NULL) hit = YES;
        // 兼容少数直接以 PersistenceHelper 命名的场景
        if (!hit && strstr(name, "PersistenceHelper") != NULL && strstr(name, ".dylib") == NULL) hit = YES;
        if (!hit) continue;

        *outName = name;
        *outHeader = _dyld_get_image_header(i);
        *outSlide = _dyld_get_image_vmaddr_slide(i);
        return YES;
    }

    // 兜底：image 0 通常就是主程序
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

#pragma mark - 欢迎页流程 hook

// 直接进入主页，跳过卡密/网络激活
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

// 原逻辑：异步调 primary/secondary，成功才 ToHome
// 现逻辑：直接 ToHome
- (void)tsh_checkActivationAndEnterHome {
    SSHHLog("tsh_checkActivationAndEnterHome hit");
    SSHHForceEnterHome(self, "checkActivation");
}

// 原逻辑 viewDidAppear 约 1.2s 后触发检查
// 这里提前一点主动触发，确保 hook 生效
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    SSHHLog("viewDidAppear animated=%d", (int)animated);

    __weak TSHWelcomeViewController *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        TSHWelcomeViewController *strongSelf = weakSelf;
        if (!strongSelf) return;
        SSHHForceEnterHome(strongSelf, "viewDidAppear");
    });
}

%end

#pragma mark - ctor

%ctor {
    @autoreleasepool {
        NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"(null)";
        NSString *exe = NSBundle.mainBundle.executablePath ?: @"(null)";
        SSHHLog("loaded bid=%@ exe=%@", bid, exe);

        // 仅在计算器场景启用
        BOOL isCalc = [bid isEqualToString:@"com.apple.calculator"] ||
                      [exe.lastPathComponent isEqualToString:@"Calculator"];
        if (!isCalc) {
            SSHHLog("not calculator, skip hooks");
            return;
        }

        // 1) 底层 return 1 兜底
        if (!SSHHInstallFunctionHooks()) {
            // 主镜像偶发未就绪时，延迟再试一次
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                SSHHInstallFunctionHooks();
            });
        }

        // 2) ObjC hook 由 Logos %hook 自动完成
        Class welcomeCls = objc_getClass("TSHWelcomeViewController");
        SSHHLog("TSHWelcomeViewController=%p", welcomeCls);
        SSHHLog("init done");
    }
}
