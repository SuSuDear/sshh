#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <notify.h>

/// Target controller identified from the Calculator binary.
/// Keeping this as a single constant makes all runtime checks narrow and auditable.
static NSString * const SSHHTargetControllerName = @"TSHWelcomeViewController";

/// Target verification alert title observed in the binary.
/// Used only for diagnostics and for dismissing the blocking activation prompt.
static NSString * const SSHHVerificationTitle = @"验证";

/// Verification-failure alert title observed in runtime logs from TSHWelcomeViewController and LogViewController.
static NSString * const SSHHVerificationFailureTitle = @"验证失败";

/// Primary file log path under a stable mobile-owned directory that survives jbroot path changes.
static NSString * const SSHHPrimaryLogPath = @"/var/mobile/SuSu/sshh.log";

/// Fallback path used if the sandbox cannot write to the workspace path.
static NSString * const SSHHFallbackLogPath = @"/tmp/sshh.log";

/// Darwin notification used to close the high-level log window from any injected runtime that owns it.
static NSString * const SSHHCloseLogNotificationName = @"com.susu.sshh.close-log-window";

/// Preference suite recovered from the binary for HUD and live-mode switches.
static NSString * const SSHHRecoveredPreferenceSuite = @"com.apple.wuxinglan";

/// Serial queue used to avoid interleaved writes from UIKit callbacks.
static dispatch_queue_t SSHHLogQueue(void) {
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("com.susu.sshh.filelog", DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

/// Appends one diagnostic line to the plugin log file and mirrors it to NSLog.
/// Critical logic: keep file writes best-effort so diagnostics never block app flow.
static void SSHHLog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static void SSHHLog(NSString *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);

    NSString *line = [NSString stringWithFormat:@"[sshh] %@", message ?: @""];
    NSLog(@"%@", line);

    dispatch_async(SSHHLogQueue(), ^{
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
        NSString *timestamp = [formatter stringFromDate:[NSDate date]];
        NSString *entry = [NSString stringWithFormat:@"%@ %@\n", timestamp, line];
        NSData *data = [entry dataUsingEncoding:NSUTF8StringEncoding];

        NSString *path = SSHHPrimaryLogPath;
        NSFileManager *fileManager = NSFileManager.defaultManager;
        NSString *directory = path.stringByDeletingLastPathComponent;
        BOOL directoryReady = [fileManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
        if (!directoryReady) {
            path = SSHHFallbackLogPath;
        }

        if (![fileManager fileExistsAtPath:path]) {
            [data writeToFile:path atomically:YES];
            return;
        }

        NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:path];
        if (fileHandle == nil && ![path isEqualToString:SSHHFallbackLogPath]) {
            path = SSHHFallbackLogPath;
            if (![fileManager fileExistsAtPath:path]) {
                [data writeToFile:path atomically:YES];
                return;
            }
            fileHandle = [NSFileHandle fileHandleForWritingAtPath:path];
        }

        if (fileHandle != nil) {
            [fileHandle seekToEndOfFile];
            [fileHandle writeData:data];
            [fileHandle closeFile];
        }
    });
}

/// Builds a stable object description for runtime logs without assuming the object type.
static NSString *SSHHDescribeObject(id object) {
    if (object == nil) {
        return @"<nil>";
    }
    return [NSString stringWithFormat:@"<%@: %p>", NSStringFromClass([object class]), object];
}

/// Returns YES only for the expected welcome controller so hooks stay narrowly scoped.
static BOOL SSHHIsTargetWelcomeController(id object) {
    Class targetClass = NSClassFromString(SSHHTargetControllerName);
    return targetClass != Nil && object != nil && [object isKindOfClass:targetClass];
}

/// Returns YES for the verification alerts proven by runtime logs to block the HUD/log workflow.
static BOOL SSHHShouldSuppressVerificationAlert(NSString *title, NSString *message, id presenter) {
    BOOL knownTitle = [title isEqualToString:SSHHVerificationTitle] || [title isEqualToString:SSHHVerificationFailureTitle];
    BOOL knownFailureText = [message containsString:@"激活码不存在"];
    BOOL knownPresenter = [presenter isKindOfClass:NSClassFromString(SSHHTargetControllerName)] || [presenter isKindOfClass:NSClassFromString(@"LogViewController")];
    // Critical logic: keep the suppression narrow to observed activation alerts, not arbitrary app alerts.
    return knownTitle && (knownFailureText || knownPresenter || [title isEqualToString:SSHHVerificationTitle]);
}

/// Finds the visible TSHWelcomeViewController by walking the presented/root hierarchy.
/// This is used by alert hooks where `self` is the presenter or alert, not the welcome VC.
static UIViewController *SSHHFindWelcomeControllerFrom(UIViewController *controller) {
    if (controller == nil) {
        return nil;
    }
    if (SSHHIsTargetWelcomeController(controller)) {
        return controller;
    }
    UIViewController *presented = controller.presentedViewController;
    if (presented != nil) {
        UIViewController *found = SSHHFindWelcomeControllerFrom(presented);
        if (found != nil) {
            return found;
        }
    }
    if ([controller isKindOfClass:[UINavigationController class]]) {
        UINavigationController *navigationController = (UINavigationController *)controller;
        for (UIViewController *child in navigationController.viewControllers) {
            UIViewController *found = SSHHFindWelcomeControllerFrom(child);
            if (found != nil) {
                return found;
            }
        }
    }
    if ([controller isKindOfClass:[UITabBarController class]]) {
        UITabBarController *tabBarController = (UITabBarController *)controller;
        for (UIViewController *child in tabBarController.viewControllers) {
            UIViewController *found = SSHHFindWelcomeControllerFrom(child);
            if (found != nil) {
                return found;
            }
        }
    }
    for (UIViewController *child in controller.childViewControllers) {
        UIViewController *found = SSHHFindWelcomeControllerFrom(child);
        if (found != nil) {
            return found;
        }
    }
    return nil;
}

/// Locates the welcome controller from the current key window scene.
/// Critical fallback: presentation hooks may fire from another controller object.
static UIViewController *SSHHFindVisibleWelcomeController(void) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        for (UIWindow *window in windowScene.windows) {
            UIViewController *found = SSHHFindWelcomeControllerFrom(window.rootViewController);
            if (found != nil) {
                return found;
            }
        }
    }
    return nil;
}

/// Calls a boolean setter safely when the target implements it.
/// This keeps the controller's own state consistent before entering Home.
static void SSHHSetBoolIfPossible(id object, SEL selector, BOOL value) {
    if (object != nil && [object respondsToSelector:selector]) {
        SSHHLog(@"set %@=%@ on %@", NSStringFromSelector(selector), value ? @"YES" : @"NO", SSHHDescribeObject(object));
        ((void (*)(id, SEL, BOOL))objc_msgSend)(object, selector, value);
    } else {
        SSHHLog(@"skip setter %@ on %@", NSStringFromSelector(selector), SSHHDescribeObject(object));
    }
}

/// Executes the final navigation primitive observed in the target binary.
/// Critical logic: pass YES to ToHome: so the original method takes the Home path.
static void SSHHForceEnterHomeNow(id controller, const char *reason) {
    SSHHLog(@"force request reason=%s controller=%@ targetClass=%@", reason ?: "unknown", SSHHDescribeObject(controller), NSClassFromString(SSHHTargetControllerName));

    if (!SSHHIsTargetWelcomeController(controller)) {
        SSHHLog(@"force aborted: controller is not target welcome controller");
        return;
    }

    SEL toHomeSelector = NSSelectorFromString(@"ToHome:");
    if (![controller respondsToSelector:toHomeSelector]) {
        SSHHLog(@"force aborted: ToHome: unavailable on %@", SSHHDescribeObject(controller));
        return;
    }

    // Mark the welcome flow as already handled to reduce repeated activation polling.
    SSHHSetBoolIfPossible(controller, NSSelectorFromString(@"setTsh_activationStarted:"), YES);
    SSHHSetBoolIfPossible(controller, NSSelectorFromString(@"setTsh_didEnterHome:"), YES);

    SSHHLog(@"calling ToHome:YES reason=%s", reason ?: "unknown");
    ((void (*)(id, SEL, BOOL))objc_msgSend)(controller, toHomeSelector, YES);
}

/// Schedules navigation on the main queue after UIKit presentation/layout settles.
static void SSHHScheduleEnterHome(id controller, const char *reason) {
    SSHHLog(@"schedule reason=%s controller=%@ isTarget=%@", reason ?: "unknown", SSHHDescribeObject(controller), SSHHIsTargetWelcomeController(controller) ? @"YES" : @"NO");

    __weak id weakController = controller;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.20 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        id strongController = weakController;
        SSHHForceEnterHomeNow(strongController, reason);
    });
}

/// Logs the available methods on the target class so we can confirm runtime names.
static void SSHHDumpTargetClass(void) {
    Class targetClass = NSClassFromString(SSHHTargetControllerName);
    SSHHLog(@"target class lookup %@ -> %@", SSHHTargetControllerName, targetClass);
    if (targetClass == Nil) {
        return;
    }

    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(targetClass, &methodCount);
    NSMutableArray<NSString *> *methodNames = [NSMutableArray array];
    for (unsigned int index = 0; index < methodCount; index++) {
        SEL selector = method_getName(methods[index]);
        if (selector != NULL) {
            [methodNames addObject:NSStringFromSelector(selector)];
        }
    }
    free(methods);
    SSHHLog(@"target method count=%u methods=%@", methodCount, methodNames);
}


/// Associated-object keys for the diagnostic HUD launch button and retained target.
static char SSHHHUDButtonKey;
static char SSHHHUDButtonTargetKey;
static char SSHHHUDOverlayTargetKey;
static char SSHHLogCloseButtonKey;
static char SSHHLoggedCompletionKey;
static char SSHHFloatingProxyButtonKey;

/// Retained top-level window so diagnostic controls stay visible without covering the HUD.
static UIWindow *SSHHHUDOverlayWindow;

/// Forward declaration for the passthrough window that only captures touches on real controls.
@interface SSHHPassthroughWindow : UIWindow
@end

/// Forward declarations used by the overlay button target implementation.
static void SSHHTryLaunchHUDFromController(UIViewController *controller);
static id SSHHObjectIvarIfPresent(id object, const char *ivarName);
static NSArray<UIWindow *> *SSHHAllRuntimeWindows(void);
static NSUInteger SSHHRestoreFloatingBallFromRuntime(UIViewController *controller, const char *reason);
static NSUInteger SSHHOpenMenuFromFloatingProxy(UIViewController *controller, id sender, const char *reason);
static void SSHHTryCloseDrawingFromController(UIViewController *controller);
static void SSHHTryToggleLiveModeFromController(UIViewController *controller);
static void SSHHTryCloseLogFromRuntime(UIViewController *controller);
static NSArray<UIWindow *> *SSHHLegacyApplicationWindows(void);
static NSUInteger SSHHHideLogWindowsFromRuntime(const char *reason);
static void SSHHSetOverlayStartButtonHidden(BOOL hidden);

/// Small Objective-C target object retained by the welcome controller.
/// It lets a normal UIButton call back into our C helper without modifying target classes.
@interface SSHHHUDButtonTarget : NSObject
@property (nonatomic, weak) UIViewController *controller;
@end

@implementation SSHHHUDButtonTarget

/// Button action: run the HUD-entry discovery routine and log every attempted call.
- (void)sshh_launchHUDButtonTapped:(UIButton *)sender {
    SSHHLog(@"HUD button tapped sender=%@ controller=%@", SSHHDescribeObject(sender), SSHHDescribeObject(self.controller));
    UIViewController *controller = self.controller ?: SSHHFindVisibleWelcomeController();
    SSHHTryLaunchHUDFromController(controller);
    NSUInteger restored = SSHHRestoreFloatingBallFromRuntime(controller, "launchButtonTapped");
    // Critical logic: hide our start button only when the original floating ball/window was actually restored.
    SSHHSetOverlayStartButtonHidden(restored > 0);
}

/// Button action: open the original floating-ball menu through a proxy control that we know receives UIKit touches.
- (void)sshh_floatingBallButtonTapped:(UIButton *)sender {
    SSHHLog(@"floating proxy button tapped sender=%@ controller=%@", SSHHDescribeObject(sender), SSHHDescribeObject(self.controller));
    UIViewController *controller = self.controller ?: SSHHFindVisibleWelcomeController();
    SSHHTryLaunchHUDFromController(controller);
    SSHHRestoreFloatingBallFromRuntime(controller, "floatingProxyTapped");
    SSHHOpenMenuFromFloatingProxy(controller, sender, "floatingProxyTapped");
}

/// Button action: trigger the app's own close-drawing handler when it exists in the live view tree.
- (void)sshh_closeDrawingButtonTapped:(UIButton *)sender {
    SSHHLog(@"close drawing button tapped sender=%@ controller=%@", SSHHDescribeObject(sender), SSHHDescribeObject(self.controller));
    SSHHTryCloseDrawingFromController(self.controller ?: SSHHFindVisibleWelcomeController());
}

/// Button action: toggle the HUD live-mode state and notify the HUD runtime.
- (void)sshh_toggleLiveModeButtonTapped:(UIButton *)sender {
    SSHHLog(@"live mode button tapped sender=%@ controller=%@", SSHHDescribeObject(sender), SSHHDescribeObject(self.controller));
    SSHHTryToggleLiveModeFromController(self.controller ?: SSHHFindVisibleWelcomeController());
}

/// Button action: close the high-level log panel from our app-level overlay.
- (void)sshh_closeLogButtonTapped:(UIButton *)sender {
    SSHHLog(@"close log button tapped sender=%@ controller=%@", SSHHDescribeObject(sender), SSHHDescribeObject(self.controller));
    /// Critical logic: notify every injected runtime first because the log panel is a high-level floating window, not an app child view.
    notify_post(SSHHCloseLogNotificationName.UTF8String);
    SSHHTryCloseLogFromRuntime(self.controller ?: SSHHFindVisibleWelcomeController());
}

@end

@implementation SSHHPassthroughWindow

/// Return nil for transparent background hits so HUD windows below can still receive taps and pans.
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hitView = [super hitTest:point withEvent:event];
    if (hitView == self || hitView == self.rootViewController.view) {
        return nil;
    }
    return hitView;
}

@end

/// Recursively collects visible controllers so we can find already-created Home/HUD objects.
static void SSHHCollectControllers(UIViewController *controller, NSMutableArray *controllers) {
    if (controller == nil || controllers == nil || [controllers containsObject:controller]) {
        return;
    }
    [controllers addObject:controller];

    if (controller.presentedViewController != nil) {
        SSHHCollectControllers(controller.presentedViewController, controllers);
    }
    if ([controller isKindOfClass:[UINavigationController class]]) {
        for (UIViewController *child in ((UINavigationController *)controller).viewControllers) {
            SSHHCollectControllers(child, controllers);
        }
    }
    if ([controller isKindOfClass:[UITabBarController class]]) {
        for (UIViewController *child in ((UITabBarController *)controller).viewControllers) {
            SSHHCollectControllers(child, controllers);
        }
    }
    for (UIViewController *child in controller.childViewControllers) {
        SSHHCollectControllers(child, controllers);
    }
}

/// Attempts a no-argument selector and records whether the object responded.
/// Critical logic: only call known HUD-entry selectors, never arbitrary runtime names.
static BOOL SSHHInvokeNoArgIfPossible(id object, SEL selector, NSString *source) {
    if (object == nil || selector == NULL) {
        return NO;
    }
    if (![object respondsToSelector:selector]) {
        SSHHLog(@"HUD candidate skip selector=%@ object=%@ source=%@", NSStringFromSelector(selector), SSHHDescribeObject(object), source);
        return NO;
    }

    SSHHLog(@"HUD candidate invoke selector=%@ object=%@ source=%@", NSStringFromSelector(selector), SSHHDescribeObject(object), source);
    @try {
        // Critical logic: invoke only vetted no-argument HUD entry selectors and keep failures logged.
        ((void (*)(id, SEL))objc_msgSend)(object, selector);
        return YES;
    } @catch (NSException *exception) {
        SSHHLog(@"HUD candidate exception selector=%@ object=%@ name=%@ reason=%@", NSStringFromSelector(selector), SSHHDescribeObject(object), exception.name, exception.reason);
        return NO;
    }
}

/// Tries all known HUD/start entry selectors on one candidate object.
static NSUInteger SSHHInvokeHUDSelectorsOnCandidate(id candidate, NSString *source) {
    NSArray<NSString *> *selectorNames = @[
        @"startButtonTapped",
        @"launchExecution",
        @"setupFloatingBall",
        @"showFloatingBall"
    ];

    NSUInteger invoked = 0;
    for (NSString *selectorName in selectorNames) {
        if (SSHHInvokeNoArgIfPossible(candidate, NSSelectorFromString(selectorName), source)) {
            invoked++;
        }
    }
    return invoked;
}

/// Main HUD discovery routine used by the injected button.
/// It first tries existing objects, then creates ViewController only as a diagnostic fallback.
static void SSHHTryLaunchHUDFromController(UIViewController *controller) {
    SSHHLog(@"HUD discovery start controller=%@", SSHHDescribeObject(controller));

    NSArray<NSString *> *classNames = @[
        @"ViewController",
        @"HUDApplication",
        @"HUDDelegate",
        @"HUDThread",
        @"HUDMainWindow",
        @"DrawRootViewController",
        @"MenuVC",
        @"HidVC"
    ];
    for (NSString *className in classNames) {
        SSHHLog(@"HUD class lookup %@ -> %@", className, NSClassFromString(className));
    }

    NSMutableArray *candidates = [NSMutableArray array];
    if (controller != nil) {
        [candidates addObject:controller];
    }
    id appDelegate = UIApplication.sharedApplication.delegate;
    if (appDelegate != nil) {
        [candidates addObject:appDelegate];
    }

    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            SSHHLog(@"HUD window candidate %@ root=%@", SSHHDescribeObject(window), SSHHDescribeObject(window.rootViewController));
            SSHHCollectControllers(window.rootViewController, candidates);
        }
    }

    NSUInteger invoked = 0;
    for (id candidate in candidates) {
        invoked += SSHHInvokeHUDSelectorsOnCandidate(candidate, @"existing-object");
    }

    Class viewControllerClass = NSClassFromString(@"ViewController");
    if (viewControllerClass != Nil) {
        id viewController = [[viewControllerClass alloc] init];
        SSHHLog(@"HUD instantiated ViewController -> %@", SSHHDescribeObject(viewController));
        invoked += SSHHInvokeHUDSelectorsOnCandidate(viewController, @"new-ViewController");
    }

    SSHHLog(@"HUD discovery finished invoked=%lu", (unsigned long)invoked);
}

/// Recursively scans subviews for buttons matching a visible title.
static void SSHHCollectButtonsMatchingTitle(UIView *view, NSString *needle, NSMutableArray<UIButton *> *matches) {
    if (view == nil || needle.length == 0 || matches == nil) {
        return;
    }
    if ([view isKindOfClass:[UIButton class]]) {
        UIButton *button = (UIButton *)view;
        NSString *title = button.currentTitle ?: [button titleForState:UIControlStateNormal];
        if ([title containsString:needle]) {
            [matches addObject:button];
            SSHHLog(@"matched button title=%@ button=%@", title, SSHHDescribeObject(button));
        }
    }
    for (UIView *subview in view.subviews) {
        SSHHCollectButtonsMatchingTitle(subview, needle, matches);
    }
}

/// Collects live controller objects from all active windows for direct HUD selector invocation.
static NSArray *SSHHCollectRuntimeCandidates(UIViewController *controller) {
    NSMutableArray *candidates = [NSMutableArray array];
    if (controller != nil) {
        [candidates addObject:controller];
    }
    id appDelegate = UIApplication.sharedApplication.delegate;
    if (appDelegate != nil) {
        [candidates addObject:appDelegate];
    }
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window == SSHHHUDOverlayWindow) {
                continue;
            }
            SSHHLog(@"runtime candidate scene-window %@ root=%@", SSHHDescribeObject(window), SSHHDescribeObject(window.rootViewController));
            SSHHCollectControllers(window.rootViewController, candidates);
        }
    }
    for (UIWindow *window in SSHHLegacyApplicationWindows()) {
        if (window == SSHHHUDOverlayWindow) {
            continue;
        }
        SSHHLog(@"runtime candidate app-window %@ root=%@", SSHHDescribeObject(window), SSHHDescribeObject(window.rootViewController));
        // Critical logic: include legacy/high-level HUD windows, because LogViewController may not be in scene.windows.
        SSHHCollectControllers(window.rootViewController, candidates);
    }
    return candidates;
}

/// Invokes a known no-argument action selector on existing runtime objects only.
static NSUInteger SSHHInvokeKnownNoArgAction(NSArray *candidates, NSString *selectorName, NSString *source) {
    SEL selector = NSSelectorFromString(selectorName);
    NSUInteger invoked = 0;
    for (id candidate in candidates) {
        if (![candidate respondsToSelector:selector]) {
            continue;
        }
        SSHHLog(@"%@ invoke selector=%@ object=%@", source, selectorName, SSHHDescribeObject(candidate));
        @try {
            // Critical logic: only call vetted HUD control selectors recovered from Calculator metadata.
            ((void (*)(id, SEL))objc_msgSend)(candidate, selector);
            invoked++;
        } @catch (NSException *exception) {
            SSHHLog(@"%@ exception selector=%@ object=%@ name=%@ reason=%@", source, selectorName, SSHHDescribeObject(candidate), exception.name, exception.reason);
        }
    }
    return invoked;
}

/// Invokes a known one-object action selector on existing runtime objects only.
static NSUInteger SSHHInvokeKnownObjectAction(NSArray *candidates, NSString *selectorName, id argument, NSString *source) {
    SEL selector = NSSelectorFromString(selectorName);
    NSUInteger invoked = 0;
    for (id candidate in candidates) {
        if (![candidate respondsToSelector:selector]) {
            continue;
        }
        SSHHLog(@"%@ invoke selector=%@ object=%@ argument=%@", source, selectorName, SSHHDescribeObject(candidate), SSHHDescribeObject(argument));
        @try {
            // Critical logic: match UIKit action signature such as liveSwitchChanged: without guessing extra args.
            ((void (*)(id, SEL, id))objc_msgSend)(candidate, selector, argument);
            invoked++;
        } @catch (NSException *exception) {
            SSHHLog(@"%@ exception selector=%@ object=%@ name=%@ reason=%@", source, selectorName, SSHHDescribeObject(candidate), exception.name, exception.reason);
        }
    }
    return invoked;
}


/// Returns both standard defaults and the recovered suite used by the original HUD code.
static NSArray<NSUserDefaults *> *SSHHRecoveredDefaultsStores(void) {
    NSMutableArray<NSUserDefaults *> *stores = [NSMutableArray arrayWithObject:NSUserDefaults.standardUserDefaults];
    NSUserDefaults *suiteDefaults = [[NSUserDefaults alloc] initWithSuiteName:SSHHRecoveredPreferenceSuite];
    if (suiteDefaults != nil) {
        [stores addObject:suiteDefaults];
    }
    return stores;
}

/// Writes a BOOL to every recovered defaults store so app code using either accessor observes the same state.
static void SSHHSetRecoveredBool(BOOL value, NSString *key) {
    for (NSUserDefaults *defaults in SSHHRecoveredDefaultsStores()) {
        [defaults setBool:value forKey:key];
        [defaults synchronize];
        SSHHLog(@"defaults set key=%@ value=%@ store=%@", key, value ? @"YES" : @"NO", SSHHDescribeObject(defaults));
    }
}

/// Reads a BOOL from the recovered suite first, then standard defaults.
static BOOL SSHHRecoveredBoolForKey(NSString *key) {
    NSArray<NSUserDefaults *> *stores = SSHHRecoveredDefaultsStores();
    for (NSUserDefaults *defaults in [stores reverseObjectEnumerator]) {
        id value = [defaults objectForKey:key];
        if (value != nil) {
            BOOL result = [defaults boolForKey:key];
            SSHHLog(@"defaults read key=%@ value=%@ store=%@", key, result ? @"YES" : @"NO", SSHHDescribeObject(defaults));
            return result;
        }
    }
    return NO;
}

/// Opens the original menu path from our proxy round button instead of trusting the original floating ball touch chain.
static NSUInteger SSHHOpenMenuFromFloatingProxy(UIViewController *controller, id sender, const char *reason) {
    NSString *source = [NSString stringWithFormat:@"%s", reason ?: "unknown"];
    NSArray *candidates = SSHHCollectRuntimeCandidates(controller);
    NSUInteger invoked = 0;

    /// Critical logic: floatingBallClicked: is the recovered original tap handler; pass our known-clickable proxy button as sender.
    invoked += SSHHInvokeKnownObjectAction(candidates, @"floatingBallClicked:", sender, [source stringByAppendingString:@":floatingBallClicked"]);
    invoked += SSHHInvokeKnownNoArgAction(candidates, @"setupMenu", [source stringByAppendingString:@":setupMenu"]);
    invoked += SSHHInvokeKnownNoArgAction(candidates, @"showFloatingBall", [source stringByAppendingString:@":showFloatingBall"]);

    Class viewControllerClass = NSClassFromString(@"ViewController");
    if (invoked == 0 && viewControllerClass != Nil) {
        id viewController = [[viewControllerClass alloc] init];
        SSHHLog(@"floating proxy instantiated ViewController=%@", SSHHDescribeObject(viewController));
        invoked += SSHHInvokeNoArgIfPossible(viewController, NSSelectorFromString(@"setupFloatingBall"), [source stringByAppendingString:@":newVC.setupFloatingBall"]);
        invoked += SSHHInvokeNoArgIfPossible(viewController, NSSelectorFromString(@"setupMenu"), [source stringByAppendingString:@":newVC.setupMenu"]);
        if ([viewController respondsToSelector:NSSelectorFromString(@"floatingBallClicked:")]) {
            ((void (*)(id, SEL, id))objc_msgSend)(viewController, NSSelectorFromString(@"floatingBallClicked:"), sender);
            invoked++;
        }
    }

    SSHHLog(@"floating proxy open finished reason=%@ invoked=%lu sender=%@", source, (unsigned long)invoked, SSHHDescribeObject(sender));
    return invoked;
}


/// Restores visibility for a view that may be the original square/circle floating ball.
static BOOL SSHHRestoreFloatingView(UIView *view, NSString *source) {
    if (![view isKindOfClass:[UIView class]]) {
        return NO;
    }
    CGRect frame = view.frame;
    SSHHLog(@"restore floating view source=%@ view=%@ class=%@ frame={%.1f,%.1f,%.1f,%.1f} hidden=%@ alpha=%.2f super=%@ window=%@", source, SSHHDescribeObject(view), NSStringFromClass([view class]), frame.origin.x, frame.origin.y, frame.size.width, frame.size.height, view.hidden ? @"YES" : @"NO", view.alpha, SSHHDescribeObject(view.superview), SSHHDescribeObject(view.window));
    /// Critical logic: restore only visibility/interaction; keep the app's own layout and gestures intact.
    view.hidden = NO;
    view.alpha = 1.0;
    view.userInteractionEnabled = YES;
    if (view.superview != nil) {
        [view.superview bringSubviewToFront:view];
    }
    return YES;
}

/// Restores HUDMainWindow / HUDDelegate.hudwindow so the floating ball can appear above other apps.
static BOOL SSHHRestoreHUDWindow(UIWindow *window, NSString *source) {
    if (![window isKindOfClass:[UIWindow class]] || window == SSHHHUDOverlayWindow) {
        return NO;
    }
    NSString *windowClass = NSStringFromClass([window class]);
    NSString *rootClass = NSStringFromClass([window.rootViewController class]);
    BOOL isHUDWindow = [windowClass containsString:@"HUDMainWindow"] || [rootClass containsString:@"ViewController"] || [rootClass containsString:@"MenuVC"];
    if (!isHUDWindow) {
        return NO;
    }
    SSHHLog(@"restore HUD window source=%@ window=%@ class=%@ root=%@ level=%.1f hidden=%@ alpha=%.2f", source, SSHHDescribeObject(window), windowClass, SSHHDescribeObject(window.rootViewController), window.windowLevel, window.hidden ? @"YES" : @"NO", window.alpha);
    /// Critical logic: the floating button is rendered in a high-level HUD window, so restore the window itself first.
    window.hidden = NO;
    window.alpha = 1.0;
    window.userInteractionEnabled = YES;
    if (window.windowLevel < UIWindowLevelAlert + 1000.0) {
        window.windowLevel = UIWindowLevelAlert + 1500.0;
    }
    [window makeKeyAndVisible];
    return YES;
}

/// Re-enables the target's original floating ball after setup/show selectors run.
static NSUInteger SSHHRestoreFloatingBallFromRuntime(UIViewController *controller, const char *reason) {
    NSString *source = [NSString stringWithFormat:@"%s", reason ?: "unknown"];
    NSUInteger restored = 0;

    /// Critical logic: enable the persisted switch used by the original floating-ball path in the recovered suite too.
    SSHHSetRecoveredBool(YES, @"FloatingBall_key");

    id appDelegate = UIApplication.sharedApplication.delegate;
    SEL hudWindowSelector = NSSelectorFromString(@"hudwindow");
    if (appDelegate != nil && [appDelegate respondsToSelector:hudWindowSelector]) {
        UIWindow *hudWindow = ((UIWindow *(*)(id, SEL))objc_msgSend)(appDelegate, hudWindowSelector);
        if (SSHHRestoreHUDWindow(hudWindow, [source stringByAppendingString:@":delegate.hudwindow"])) {
            restored++;
        }
    }
    UIWindow *ivarHUDWindow = SSHHObjectIvarIfPresent(appDelegate, "_hudwindow");
    if (SSHHRestoreHUDWindow(ivarHUDWindow, [source stringByAppendingString:@":delegate._hudwindow"])) {
        restored++;
    }

    NSArray *candidates = SSHHCollectRuntimeCandidates(controller);
    for (id candidate in candidates) {
        SEL floatingSelector = NSSelectorFromString(@"floatingBall");
        if ([candidate respondsToSelector:floatingSelector]) {
            UIView *floatingBall = ((UIView *(*)(id, SEL))objc_msgSend)(candidate, floatingSelector);
            if (SSHHRestoreFloatingView(floatingBall, [source stringByAppendingString:@":candidate.floatingBall"])) {
                restored++;
            }
        }
        Ivar ivar = class_getInstanceVariable([candidate class], "floatingBall");
        if (ivar != NULL) {
            UIView *floatingBall = object_getIvar(candidate, ivar);
            if (SSHHRestoreFloatingView(floatingBall, [source stringByAppendingString:@":candidate.ivarFloatingBall"])) {
                restored++;
            }
        }
    }

    for (UIWindow *window in SSHHAllRuntimeWindows()) {
        if (SSHHRestoreHUDWindow(window, [source stringByAppendingString:@":window-scan"])) {
            restored++;
        }
    }

    SSHHLog(@"restore floating ball finished reason=%@ restored=%lu", source, (unsigned long)restored);
    return restored;
}


/// Returns the live LogViewController using the app's HUDDelegate.logVC first, then falls back to window traversal.
/// Critical logic: the log panel is owned by HUDDelegate._logwindow, so ordinary scene windows may miss it.
static id SSHHFindLogControllerFromRuntime(UIViewController *controller) {
    SEL logVCSelector = NSSelectorFromString(@"logVC");
    id appDelegate = UIApplication.sharedApplication.delegate;
    if (appDelegate != nil && [appDelegate respondsToSelector:logVCSelector]) {
        id logController = ((id (*)(id, SEL))objc_msgSend)(appDelegate, logVCSelector);
        SSHHLog(@"log controller via appDelegate.logVC appDelegate=%@ logVC=%@", SSHHDescribeObject(appDelegate), SSHHDescribeObject(logController));
        if (logController != nil) {
            return logController;
        }
    }

    NSArray *candidates = SSHHCollectRuntimeCandidates(controller);
    Class logClass = NSClassFromString(@"LogViewController");
    for (id candidate in candidates) {
        if (logClass != Nil && [candidate isKindOfClass:logClass]) {
            SSHHLog(@"log controller via runtime candidate=%@", SSHHDescribeObject(candidate));
            return candidate;
        }
        if ([candidate respondsToSelector:logVCSelector]) {
            id logController = ((id (*)(id, SEL))objc_msgSend)(candidate, logVCSelector);
            SSHHLog(@"log controller via candidate.logVC candidate=%@ logVC=%@", SSHHDescribeObject(candidate), SSHHDescribeObject(logController));
            if (logController != nil) {
                return logController;
            }
        }
    }
    return nil;
}

/// Enables the original LogViewController close path and keeps close controls above the secure/log text views.
/// Critical logic: do not create new state; only force the recovered canCloseLogPanel property and revive existing closeButton.
static void SSHHConfigureLogPanelForTouch(id logController, const char *reason) {
    if (logController == nil) {
        SSHHLog(@"configure log panel skipped reason=%s logController=<nil>", reason ?: "unknown");
        return;
    }

    SSHHLog(@"configure log panel reason=%s controller=%@", reason ?: "unknown", SSHHDescribeObject(logController));
    SSHHSetBoolIfPossible(logController, NSSelectorFromString(@"setCanCloseLogPanel:"), YES);

    UIViewController *viewController = [logController isKindOfClass:[UIViewController class]] ? (UIViewController *)logController : nil;
    UIView *rootView = viewController.view;
    SEL closeButtonSelector = NSSelectorFromString(@"closeButton");
    if (rootView != nil && [logController respondsToSelector:closeButtonSelector]) {
        UIButton *closeButton = ((UIButton *(*)(id, SEL))objc_msgSend)(logController, closeButtonSelector);
        SSHHLog(@"original log closeButton=%@ superview=%@ hidden=%@ alpha=%.3f userInteraction=%@", SSHHDescribeObject(closeButton), SSHHDescribeObject(closeButton.superview), closeButton.hidden ? @"YES" : @"NO", closeButton.alpha, closeButton.userInteractionEnabled ? @"YES" : @"NO");
        if ([closeButton isKindOfClass:[UIButton class]]) {
            closeButton.hidden = NO;
            closeButton.alpha = 1.0;
            closeButton.userInteractionEnabled = YES;
            closeButton.exclusiveTouch = NO;
            [closeButton addTarget:logController action:@selector(closePage) forControlEvents:UIControlEventTouchUpInside];
            [rootView bringSubviewToFront:closeButton];
        }
    }

    UIView *associatedButton = objc_getAssociatedObject(logController, &SSHHLogCloseButtonKey);
    if (associatedButton != nil && rootView != nil) {
        associatedButton.hidden = NO;
        associatedButton.userInteractionEnabled = YES;
        [rootView bringSubviewToFront:associatedButton];
        SSHHLog(@"emergency log close button raised button=%@", SSHHDescribeObject(associatedButton));
    }
}

/// Logs a compact body preview for activation/network responses without dumping large binary data.
static NSString *SSHHBodyPreview(NSData *data) {
    if (![data isKindOfClass:[NSData class]] || data.length == 0) {
        return @"";
    }
    NSUInteger length = MIN((NSUInteger)1024, data.length);
    NSData *prefix = [data subdataWithRange:NSMakeRange(0, length)];
    NSString *text = [[NSString alloc] initWithData:prefix encoding:NSUTF8StringEncoding];
    if (text.length == 0) {
        text = [prefix base64EncodedStringWithOptions:0];
    }
    return text ?: @"";
}


/// Reads an Objective-C object ivar only when the runtime class really declares it.
/// Critical logic: this avoids relying on normal window hierarchy when HUDDelegate owns a private _logwindow.
static id SSHHObjectIvarIfPresent(id object, const char *ivarName) {
    if (object == nil || ivarName == NULL) {
        return nil;
    }
    Ivar ivar = class_getInstanceVariable([object class], ivarName);
    if (ivar == NULL) {
        return nil;
    }
    return object_getIvar(object, ivar);
}

/// Returns the deprecated UIApplication.windows list through objc_msgSend so high-level legacy HUD windows are still visible to us.
static NSArray<UIWindow *> *SSHHLegacyApplicationWindows(void) {
    SEL appWindowsSelector = NSSelectorFromString(@"windows");
    if (![UIApplication.sharedApplication respondsToSelector:appWindowsSelector]) {
        return @[];
    }
    /// Critical logic: keep legacy/high-level windows reachable without compiling against the deprecated property directly.
    NSArray<UIWindow *> *windows = ((NSArray<UIWindow *> *(*)(id, SEL))objc_msgSend)(UIApplication.sharedApplication, appWindowsSelector);
    return [windows isKindOfClass:[NSArray class]] ? windows : @[];
}

/// Collects scene and legacy windows in the current runtime.
static NSArray<UIWindow *> *SSHHAllRuntimeWindows(void) {
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window != nil && ![windows containsObject:window]) {
                [windows addObject:window];
            }
        }
    }
    for (UIWindow *window in SSHHLegacyApplicationWindows()) {
        if (window != nil && ![windows containsObject:window]) {
            [windows addObject:window];
        }
    }
    return windows;
}

/// Returns YES for the known high-level log window that displays status text such as 加载成功 / 现在可关闭日志.
static BOOL SSHHIsLogWindowCandidate(UIWindow *window) {
    if (window == nil || window == SSHHHUDOverlayWindow) {
        return NO;
    }
    NSString *windowClass = NSStringFromClass([window class]);
    NSString *rootClass = NSStringFromClass([window.rootViewController class]);
    NSString *description = window.description ?: @"";
    Class logControllerClass = NSClassFromString(@"LogViewController");
    BOOL hasLogRoot = logControllerClass != Nil && [window.rootViewController isKindOfClass:logControllerClass];
    BOOL namedLogWindow = [windowClass containsString:@"LOGRootWindow"] || [windowClass containsString:@"LogWindow"] || [description containsString:@"LOGRootWindow"];
    BOOL namedLogRoot = [rootClass containsString:@"LogViewController"];
    /// Critical logic: require either the recovered LogViewController root or the recovered LOGRootWindow class name.
    return hasLogRoot || namedLogWindow || namedLogRoot;
}

/// Hides one log window without destroying it, so the operation is reversible by the target if it recreates/shows it later.
static BOOL SSHHHideLogWindow(UIWindow *window, NSString *source) {
    if (!SSHHIsLogWindowCandidate(window)) {
        return NO;
    }
    SSHHLog(@"hide log window source=%@ window=%@ class=%@ root=%@ level=%.1f hidden=%@ alpha=%.2f", source, SSHHDescribeObject(window), NSStringFromClass([window class]), SSHHDescribeObject(window.rootViewController), window.windowLevel, window.hidden ? @"YES" : @"NO", window.alpha);
    /// Critical logic: disable visibility and interaction at the UIWindow level because the panel floats above normal app views.
    window.userInteractionEnabled = NO;
    window.alpha = 0.0;
    window.hidden = YES;
    window.rootViewController.view.hidden = YES;
    return YES;
}

/// Directly closes the high-level log panel by hiding HUDDelegate.logwindow/_logwindow and any LOGRootWindow candidates.
static NSUInteger SSHHHideLogWindowsFromRuntime(const char *reason) {
    NSString *source = [NSString stringWithFormat:@"%s", reason ?: "unknown"];
    NSUInteger hiddenCount = 0;
    id appDelegate = UIApplication.sharedApplication.delegate;

    SEL logWindowSelector = NSSelectorFromString(@"logwindow");
    if (appDelegate != nil && [appDelegate respondsToSelector:logWindowSelector]) {
        UIWindow *logWindow = ((UIWindow *(*)(id, SEL))objc_msgSend)(appDelegate, logWindowSelector);
        if (SSHHHideLogWindow(logWindow, [source stringByAppendingString:@":delegate.logwindow"])) {
            hiddenCount++;
        }
    }

    UIWindow *ivarLogWindow = SSHHObjectIvarIfPresent(appDelegate, "_logwindow");
    if (SSHHHideLogWindow(ivarLogWindow, [source stringByAppendingString:@":delegate._logwindow"])) {
        hiddenCount++;
    }

    id logController = SSHHFindLogControllerFromRuntime(nil);
    if ([logController isKindOfClass:[UIViewController class]]) {
        UIWindow *controllerWindow = ((UIViewController *)logController).view.window;
        if (SSHHHideLogWindow(controllerWindow, [source stringByAppendingString:@":logVC.view.window"])) {
            hiddenCount++;
        }
    }

    for (UIWindow *window in SSHHAllRuntimeWindows()) {
        if (SSHHHideLogWindow(window, [source stringByAppendingString:@":window-scan"])) {
            hiddenCount++;
        }
    }

    SSHHLog(@"hide log windows finished reason=%@ hiddenCount=%lu", source, (unsigned long)hiddenCount);
    return hiddenCount;
}

/// Hides or shows the overlay start button by title, leaving the close-drawing button available.
static void SSHHSetOverlayStartButtonHidden(BOOL hidden) {
    if (SSHHHUDOverlayWindow == nil) {
        return;
    }
    NSMutableArray<UIButton *> *matches = [NSMutableArray array];
    SSHHCollectButtonsMatchingTitle(SSHHHUDOverlayWindow.rootViewController.view, @"启动HUD", matches);
    for (UIButton *button in matches) {
        button.hidden = hidden;
        SSHHLog(@"set overlay start button hidden=%@ button=%@", hidden ? @"YES" : @"NO", SSHHDescribeObject(button));
    }
}

/// Tries to close drawing through the recovered closeTapped selector, then falls back to visible buttons.
static void SSHHTryCloseDrawingFromController(UIViewController *controller) {
    SSHHLog(@"close drawing discovery start controller=%@", SSHHDescribeObject(controller));

    NSArray *candidates = SSHHCollectRuntimeCandidates(controller);
    NSUInteger invoked = SSHHInvokeKnownNoArgAction(candidates, @"closeTapped", @"close drawing");
    if (invoked > 0) {
        SSHHLog(@"close drawing finished via closeTapped invoked=%lu", (unsigned long)invoked);
        return;
    }

    NSMutableArray<UIButton *> *matches = [NSMutableArray array];
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window == SSHHHUDOverlayWindow) {
                continue;
            }
            SSHHCollectButtonsMatchingTitle(window, @"关闭绘制", matches);
        }
    }

    if (matches.count == 0) {
        SSHHLog(@"close drawing failed: no closeTapped responder and no visible button titled 关闭绘制");
        return;
    }

    for (UIButton *button in matches) {
        SSHHLog(@"close drawing invoking original button=%@ title=%@", SSHHDescribeObject(button), button.currentTitle ?: [button titleForState:UIControlStateNormal]);
        [button sendActionsForControlEvents:UIControlEventTouchUpInside];
    }
}

/// Toggles live mode using recovered live_key, liveSwitchChanged:, refreshLiveMode, and Darwin notification strings.
static void SSHHTryToggleLiveModeFromController(UIViewController *controller) {
    SSHHLog(@"live mode discovery start controller=%@", SSHHDescribeObject(controller));

    BOOL nextEnabled = !SSHHRecoveredBoolForKey(@"live_key");
    SSHHSetRecoveredBool(nextEnabled, @"live_key");

    UISwitch *senderSwitch = [UISwitch new];
    senderSwitch.on = nextEnabled;
    NSArray *candidates = SSHHCollectRuntimeCandidates(controller);
    NSUInteger switchInvoked = SSHHInvokeKnownObjectAction(candidates, @"liveSwitchChanged:", senderSwitch, @"live mode");
    NSUInteger refreshInvoked = SSHHInvokeKnownNoArgAction(candidates, @"refreshLiveMode", @"live mode");

    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier ?: @"com.apple.calculator";
    NSArray<NSString *> *notificationNames = @[
        [NSString stringWithFormat:@"%@.notification.hud.live-mode-changed", bundleID],
        @"com.apple.calculator.notification.hud.live-mode-changed"
    ];
    for (NSString *notificationName in notificationNames) {
        /// Critical logic: notify the HUD path recovered from strings after syncing the recovered preference suite.
        notify_post(notificationName.UTF8String);
        SSHHLog(@"live mode notified name=%@", notificationName);
    }
    SSHHLog(@"live mode finished enabled=%@ switchInvoked=%lu refreshInvoked=%lu", nextEnabled ? @"YES" : @"NO", (unsigned long)switchInvoked, (unsigned long)refreshInvoked);
}


/// Closes the log floating panel from our app-level controls by invoking the recovered closePage action.
static void SSHHTryCloseLogFromRuntime(UIViewController *controller) {
    SSHHLog(@"close log discovery start controller=%@", SSHHDescribeObject(controller));

    NSUInteger hiddenBefore = SSHHHideLogWindowsFromRuntime("buttonBeforeClosePage");
    id logController = SSHHFindLogControllerFromRuntime(controller);
    if (logController != nil && [logController respondsToSelector:@selector(closePage)]) {
        SSHHConfigureLogPanelForTouch(logController, "appOverlayClose");
        SSHHLog(@"close log invoking delegate/runtime logController.closePage object=%@", SSHHDescribeObject(logController));
        @try {
            /// Critical logic: still call the app's original close path, but do not trust it as the only close mechanism.
            ((void (*)(id, SEL))objc_msgSend)(logController, @selector(closePage));
        } @catch (NSException *exception) {
            SSHHLog(@"close log direct closePage exception object=%@ name=%@ reason=%@", SSHHDescribeObject(logController), exception.name, exception.reason);
        }
    }

    NSArray *candidates = SSHHCollectRuntimeCandidates(controller);
    NSUInteger invoked = SSHHInvokeKnownNoArgAction(candidates, @"closePage", @"close log");
    NSUInteger hiddenAfter = SSHHHideLogWindowsFromRuntime("buttonAfterClosePage");
    SSHHLog(@"close log finished hiddenBefore=%lu closePageInvoked=%lu hiddenAfter=%lu", (unsigned long)hiddenBefore, (unsigned long)invoked, (unsigned long)hiddenAfter);
}

/// Adds a visible diagnostic button to the activation screen.
/// The button does not hide alerts; it only exposes and logs the existing HUD launch path.
static void SSHHInstallHUDButtonIfNeeded(id controllerObject) {
    if (!SSHHIsTargetWelcomeController(controllerObject)) {
        return;
    }
    UIViewController *controller = (UIViewController *)controllerObject;
    if (controller.view == nil) {
        return;
    }

    if (objc_getAssociatedObject(controller, &SSHHHUDButtonKey) == nil) {
        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        button.frame = CGRectMake(24.0, 260.0, 160.0, 44.0);
        button.autoresizingMask = UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleBottomMargin;
        button.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.65];
        button.layer.cornerRadius = 10.0;
        [button setTitle:@"启动HUD" forState:UIControlStateNormal];
        [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

        SSHHHUDButtonTarget *target = [SSHHHUDButtonTarget new];
        target.controller = controller;
        [button addTarget:target action:@selector(sshh_launchHUDButtonTapped:) forControlEvents:UIControlEventTouchUpInside];

        [controller.view addSubview:button];
        objc_setAssociatedObject(controller, &SSHHHUDButtonKey, button, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(controller, &SSHHHUDButtonTargetKey, target, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        SSHHLog(@"HUD button installed on %@ button=%@", SSHHDescribeObject(controller), SSHHDescribeObject(button));
    }

    if (SSHHHUDOverlayWindow != nil) {
        SSHHLog(@"HUD top overlay button already installed window=%@", SSHHDescribeObject(SSHHHUDOverlayWindow));
        return;
    }

    UIWindowScene *activeWindowScene = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        activeWindowScene = (UIWindowScene *)scene;
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            break;
        }
    }

    CGRect overlayFrame = CGRectMake(24.0, 64.0, 170.0, 256.0);
    UIWindow *overlayWindow = nil;
    if (activeWindowScene != nil) {
        overlayWindow = [[SSHHPassthroughWindow alloc] initWithWindowScene:activeWindowScene];
        overlayWindow.frame = overlayFrame;
    } else {
        overlayWindow = [[SSHHPassthroughWindow alloc] initWithFrame:overlayFrame];
    }

    UIViewController *rootController = [UIViewController new];
    rootController.view.backgroundColor = UIColor.clearColor;
    rootController.view.frame = CGRectMake(0.0, 0.0, overlayFrame.size.width, overlayFrame.size.height);
    overlayWindow.rootViewController = rootController;
    overlayWindow.backgroundColor = UIColor.clearColor;
    // Critical logic: keep this tiny window above normal app, alert, and FLEX windows so the button is tappable.
    overlayWindow.windowLevel = UIWindowLevelAlert + 2000.0;
    overlayWindow.hidden = NO;

    UIButton *overlayButton = [UIButton buttonWithType:UIButtonTypeSystem];
    overlayButton.frame = CGRectMake(0.0, 0.0, overlayFrame.size.width, 48.0);
    overlayButton.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleBottomMargin;
    overlayButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.35 blue:1.0 alpha:0.85];
    overlayButton.layer.cornerRadius = 10.0;
    [overlayButton setTitle:@"启动HUD" forState:UIControlStateNormal];
    [overlayButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    UIButton *closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    closeButton.frame = CGRectMake(0.0, 68.0, overlayFrame.size.width, 48.0);
    closeButton.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    closeButton.backgroundColor = [UIColor colorWithRed:0.8 green:0.15 blue:0.15 alpha:0.85];
    closeButton.layer.cornerRadius = 10.0;
    [closeButton setTitle:@"关闭绘制" forState:UIControlStateNormal];
    [closeButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    UIButton *liveButton = [UIButton buttonWithType:UIButtonTypeSystem];
    liveButton.frame = CGRectMake(0.0, 136.0, overlayFrame.size.width, 48.0);
    liveButton.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    liveButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.6 blue:0.25 alpha:0.85];
    liveButton.layer.cornerRadius = 10.0;
    [liveButton setTitle:@"直播模式" forState:UIControlStateNormal];
    [liveButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    UIButton *logButton = [UIButton buttonWithType:UIButtonTypeSystem];
    logButton.frame = CGRectMake(0.0, 204.0, overlayFrame.size.width, 48.0);
    logButton.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    logButton.backgroundColor = [UIColor colorWithRed:0.55 green:0.2 blue:0.8 alpha:0.85];
    logButton.layer.cornerRadius = 10.0;
    [logButton setTitle:@"关闭日志浮窗" forState:UIControlStateNormal];
    [logButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    SSHHHUDButtonTarget *overlayTarget = [SSHHHUDButtonTarget new];
    overlayTarget.controller = controller;
    UIButton *floatingProxyButton = [UIButton buttonWithType:UIButtonTypeSystem];
    floatingProxyButton.frame = CGRectMake(112.0, 4.0, 52.0, 52.0);
    floatingProxyButton.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleBottomMargin;
    floatingProxyButton.backgroundColor = [UIColor colorWithRed:1.0 green:0.55 blue:0.05 alpha:0.92];
    floatingProxyButton.layer.cornerRadius = 26.0;
    floatingProxyButton.layer.borderWidth = 2.0;
    floatingProxyButton.layer.borderColor = UIColor.whiteColor.CGColor;
    [floatingProxyButton setTitle:@"●" forState:UIControlStateNormal];
    [floatingProxyButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    [overlayButton addTarget:overlayTarget action:@selector(sshh_launchHUDButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [floatingProxyButton addTarget:overlayTarget action:@selector(sshh_floatingBallButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [closeButton addTarget:overlayTarget action:@selector(sshh_closeDrawingButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [liveButton addTarget:overlayTarget action:@selector(sshh_toggleLiveModeButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [logButton addTarget:overlayTarget action:@selector(sshh_closeLogButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [rootController.view addSubview:overlayButton];
    [rootController.view addSubview:floatingProxyButton];
    [rootController.view addSubview:closeButton];
    [rootController.view addSubview:liveButton];
    [rootController.view addSubview:logButton];
    objc_setAssociatedObject(rootController, &SSHHHUDOverlayTargetKey, overlayTarget, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(rootController, &SSHHFloatingProxyButtonKey, floatingProxyButton, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    SSHHHUDOverlayWindow = overlayWindow;
    SSHHLog(@"HUD top overlay buttons installed window=%@ startButton=%@ floatingProxy=%@ closeButton=%@ liveButton=%@ logButton=%@ scene=%@", SSHHDescribeObject(overlayWindow), SSHHDescribeObject(overlayButton), SSHHDescribeObject(floatingProxyButton), SSHHDescribeObject(closeButton), SSHHDescribeObject(liveButton), SSHHDescribeObject(logButton), SSHHDescribeObject(activeWindowScene));
}

%hook TSHWelcomeViewController

/// Preserve original setup, then log and schedule the controlled transition.
- (void)viewDidLoad {
    SSHHLog(@"TSHWelcomeViewController viewDidLoad self=%@", SSHHDescribeObject(self));
    %orig;
    SSHHScheduleEnterHome(self, "viewDidLoad");
    SSHHInstallHUDButtonIfNeeded(self);
}

/// viewDidAppear: is the most reliable point because the controller is on screen.
- (void)viewDidAppear:(BOOL)animated {
    SSHHLog(@"TSHWelcomeViewController viewDidAppear animated=%@ self=%@", animated ? @"YES" : @"NO", SSHHDescribeObject(self));
    %orig;
    SSHHScheduleEnterHome(self, "viewDidAppear");
    SSHHInstallHUDButtonIfNeeded(self);
}

/// Replace the activation poll/check with the already identified final transition.
- (void)tsh_checkActivationAndEnterHome {
    SSHHLog(@"tsh_checkActivationAndEnterHome intercepted self=%@", SSHHDescribeObject(self));
    SSHHScheduleEnterHome(self, "tsh_checkActivationAndEnterHome");
}

/// Log all calls into ToHome: and force the original implementation to receive YES.
/// This directly tests whether the final navigation branch is still being reached.
- (void)ToHome:(BOOL)enterHome {
    SSHHLog(@"ToHome: intercepted originalArg=%@ self=%@ -> calling %%orig(YES)", enterHome ? @"YES" : @"NO", SSHHDescribeObject(self));
    %orig(YES);
}

%end

%hook UIViewController

/// Diagnostic hook for modal presentations. If the activation alert is presented,
/// log the presenter and dismiss that alert before trying the known Home path again.
- (void)presentViewController:(UIViewController *)viewControllerToPresent animated:(BOOL)flag completion:(void (^)(void))completion {
    NSString *title = nil;
    NSString *message = nil;
    if ([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)viewControllerToPresent;
        title = alert.title;
        message = alert.message;
        SSHHLog(@"present UIAlertController title=%@ message=%@ presenter=%@", title, message, SSHHDescribeObject(self));
    } else {
        SSHHLog(@"present controller=%@ presenter=%@", SSHHDescribeObject(viewControllerToPresent), SSHHDescribeObject(self));
    }

    if (SSHHShouldSuppressVerificationAlert(title, message, self)) {
        SSHHLog(@"suppressing verification alert title=%@ message=%@ presenter=%@", title, message, SSHHDescribeObject(self));
        UIViewController *welcomeController = SSHHFindWelcomeControllerFrom(self) ?: SSHHFindVisibleWelcomeController();
        if (welcomeController != nil) {
            SSHHScheduleEnterHome(welcomeController, "presentVerificationAlert");
        }
        if (completion != nil) {
            completion();
        }
        return;
    }

    %orig(viewControllerToPresent, flag, completion);
}

%end

%hook UIAlertController

/// Extra alert lifecycle logging to catch alerts that bypass the generic presenter hook.
- (void)viewDidAppear:(BOOL)animated {
    SSHHLog(@"UIAlertController viewDidAppear title=%@ message=%@ self=%@", self.title, self.message, SSHHDescribeObject(self));
    %orig;
    if (SSHHShouldSuppressVerificationAlert(self.title, self.message, self.presentingViewController)) {
        SSHHLog(@"dismissing already-presented verification alert title=%@ presenter=%@", self.title, SSHHDescribeObject(self.presentingViewController));
        // Critical logic: dismiss stale high-level verification alerts that were presented before the hook returned.
        [self dismissViewControllerAnimated:NO completion:nil];
    }
}

%end

%hook LogViewController

/// Force the log panel to report that it is closable so its own close path is enabled.
- (BOOL)canCloseLogPanel {
    SSHHLog(@"LogViewController canCloseLogPanel forced YES self=%@", SSHHDescribeObject(self));
    return YES;
}

/// Keep the backing ivar/property enabled even if original code tries to disable the close panel.
- (void)setCanCloseLogPanel:(BOOL)enabled {
    SSHHLog(@"LogViewController setCanCloseLogPanel intercepted original=%@ self=%@ -> YES", enabled ? @"YES" : @"NO", SSHHDescribeObject(self));
    %orig(YES);
}

/// Log and preserve the original close path; both original and injected buttons invoke this selector.
- (void)closePage {
    SSHHLog(@"LogViewController closePage intercepted self=%@", SSHHDescribeObject(self));
    SSHHConfigureLogPanelForTouch(self, "beforeClosePage");
    %orig;
}

/// Bypass the panel's button-area filter while logging the original answer for evidence.
- (BOOL)isTouchInButtonArea:(CGPoint)point {
    BOOL originalResult = %orig(point);
    SSHHLog(@"LogViewController isTouchInButtonArea point={%.1f, %.1f} original=%@ self=%@ -> YES", point.x, point.y, originalResult ? @"YES" : @"NO", SSHHDescribeObject(self));
    /// Critical logic: return YES so touches on revived/injected close buttons are not rejected by the panel filter.
    return YES;
}

/// Prevent pan/scroll gestures from stealing touches that land on UIButtons or their labels.
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldReceiveTouch:(UITouch *)touch {
    UIView *touchedView = touch.view;
    BOOL touchesButton = NO;
    for (UIView *view = touchedView; view != nil; view = view.superview) {
        if ([view isKindOfClass:[UIButton class]]) {
            touchesButton = YES;
            break;
        }
    }
    if (touchesButton) {
        SSHHLog(@"LogViewController gesture %@ shouldReceiveTouch button-view=%@ -> NO", SSHHDescribeObject(gestureRecognizer), SSHHDescribeObject(touchedView));
        /// Critical logic: returning NO lets UIButton receive TouchUpInside instead of the panel pan/scroll gesture.
        return NO;
    }
    BOOL result = %orig(gestureRecognizer, touch);
    SSHHLog(@"LogViewController gesture %@ shouldReceiveTouch view=%@ original=%@", SSHHDescribeObject(gestureRecognizer), SSHHDescribeObject(touchedView), result ? @"YES" : @"NO");
    return result;
}

/// Log hit-testing on the root log view to prove whether the close buttons are under a secure/text overlay.
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *result = %orig(point, event);
    SSHHLog(@"LogViewController hitTest point={%.1f, %.1f} result=%@ self=%@", point.x, point.y, SSHHDescribeObject(result), SSHHDescribeObject(self));
    return result;
}

/// Add a small emergency close button above the log panel in case the original close control is hidden by window level.
- (void)viewDidAppear:(BOOL)animated {
    SSHHLog(@"LogViewController viewDidAppear animated=%@ self=%@", animated ? @"YES" : @"NO", SSHHDescribeObject(self));
    %orig;
    SSHHConfigureLogPanelForTouch(self, "viewDidAppear");
    UIViewController *controller = (UIViewController *)self;
    if (controller.view == nil || objc_getAssociatedObject(self, &SSHHLogCloseButtonKey) != nil) {
        return;
    }
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = CGRectMake(24.0, 44.0, 136.0, 44.0);
    button.autoresizingMask = UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleBottomMargin;
    button.backgroundColor = [UIColor colorWithRed:0.8 green:0.1 blue:0.1 alpha:0.9];
    button.layer.cornerRadius = 8.0;
    button.userInteractionEnabled = YES;
    button.exclusiveTouch = NO;
    [button setTitle:@"关闭日志" forState:UIControlStateNormal];
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    /// Critical logic: call the app's recovered closePage action directly; no private state is modified here.
    [button addTarget:self action:@selector(closePage) forControlEvents:UIControlEventTouchUpInside];
    [controller.view addSubview:button];
    [controller.view bringSubviewToFront:button];
    objc_setAssociatedObject(self, &SSHHLogCloseButtonKey, button, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    SSHHLog(@"LogViewController emergency close button installed button=%@", SSHHDescribeObject(button));
}

%end



%hook NSURL

/// Log activation/network URL construction so split or runtime-built domains become visible.
+ (instancetype)URLWithString:(NSString *)URLString {
    if ([URLString containsString:@"http"] || [URLString containsString:@"banxia"] || [URLString containsString:@".cc"]) {
        SSHHLog(@"NSURL URLWithString: %@", URLString);
    }
    return %orig;
}

%end

%hook NSURLSession

/// Wrap URL-based tasks to log request URL and response body preview from activation checks.
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    SSHHLog(@"NSURLSession dataTaskWithURL url=%@ completion=%@", url.absoluteString, completionHandler ? @"YES" : @"NO");
    void (^wrappedCompletion)(NSData *, NSURLResponse *, NSError *) = completionHandler;
    if (completionHandler != nil && objc_getAssociatedObject(completionHandler, &SSHHLoggedCompletionKey) == nil) {
        wrappedCompletion = ^(NSData *data, NSURLResponse *response, NSError *error) {
            NSInteger statusCode = [response respondsToSelector:@selector(statusCode)] ? ((NSInteger (*)(id, SEL))objc_msgSend)(response, @selector(statusCode)) : -1;
            SSHHLog(@"NSURLSession dataTaskWithURL completion url=%@ status=%ld error=%@ bytes=%lu body=%@", url.absoluteString, (long)statusCode, error, (unsigned long)data.length, SSHHBodyPreview(data));
            completionHandler(data, response, error);
        };
        objc_setAssociatedObject(wrappedCompletion, &SSHHLoggedCompletionKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return %orig(url, wrappedCompletion);
}

/// Wrap request-based tasks as a fallback for activation checks that use NSMutableURLRequest.
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    SSHHLog(@"NSURLSession dataTaskWithRequest url=%@ method=%@ completion=%@", request.URL.absoluteString, request.HTTPMethod, completionHandler ? @"YES" : @"NO");
    void (^wrappedCompletion)(NSData *, NSURLResponse *, NSError *) = completionHandler;
    if (completionHandler != nil && objc_getAssociatedObject(completionHandler, &SSHHLoggedCompletionKey) == nil) {
        wrappedCompletion = ^(NSData *data, NSURLResponse *response, NSError *error) {
            NSInteger statusCode = [response respondsToSelector:@selector(statusCode)] ? ((NSInteger (*)(id, SEL))objc_msgSend)(response, @selector(statusCode)) : -1;
            SSHHLog(@"NSURLSession dataTaskWithRequest completion url=%@ status=%ld error=%@ bytes=%lu body=%@", request.URL.absoluteString, (long)statusCode, error, (unsigned long)data.length, SSHHBodyPreview(data));
            completionHandler(data, response, error);
        };
        objc_setAssociatedObject(wrappedCompletion, &SSHHLoggedCompletionKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return %orig(request, wrappedCompletion);
}

%end

%hook NSJSONSerialization

/// Log decoded JSON from activation responses so the success/error schema is visible before deciding a spoof point.
+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)error {
    id object = %orig(data, opt, error);
    SSHHLog(@"NSJSONSerialization JSONObjectWithData bytes=%lu object=%@ error=%@ preview=%@", (unsigned long)data.length, object, error ? *error : nil, SSHHBodyPreview(data));
    return object;
}

%end

%hook ViewController

/// Log the original HUD start button handler if the hidden home controller reaches it.
- (void)startButtonTapped {
    SSHHLog(@"ViewController startButtonTapped intercepted self=%@", SSHHDescribeObject(self));
    %orig;
}

/// Log the lower-level launch method identified from Objective-C metadata.
- (void)launchExecution {
    SSHHLog(@"ViewController launchExecution intercepted self=%@", SSHHDescribeObject(self));
    %orig;
}

/// Log floating-ball setup because it is likely the visible HUD entry.
- (void)setupFloatingBall {
    SSHHLog(@"ViewController setupFloatingBall intercepted self=%@", SSHHDescribeObject(self));
    %orig;
    SSHHRestoreFloatingBallFromRuntime((UIViewController *)self, "setupFloatingBall");
}

/// Log floating-ball display to determine whether manual invocation reaches visible UI.
- (void)showFloatingBall {
    SSHHLog(@"ViewController showFloatingBall intercepted self=%@", SSHHDescribeObject(self));
    %orig;
    SSHHRestoreFloatingBallFromRuntime((UIViewController *)self, "showFloatingBall");
}

/// Log the recovered original floating-ball tap handler to verify whether our proxy reaches the menu path.
- (void)floatingBallClicked:(id)sender {
    SSHHLog(@"ViewController floatingBallClicked: intercepted self=%@ sender=%@", SSHHDescribeObject(self), SSHHDescribeObject(sender));
    %orig;
}

/// Log the original menu setup path because a missing menu explains a visible but ineffective floating ball.
- (void)setupMenu {
    SSHHLog(@"ViewController setupMenu intercepted self=%@", SSHHDescribeObject(self));
    %orig;
}

/// Log forced floating-ball active state changes from the target itself.
- (void)setFloatingBallActive:(BOOL)active {
    SSHHLog(@"ViewController setFloatingBallActive: intercepted self=%@ active=%@", SSHHDescribeObject(self), active ? @"YES" : @"NO");
    %orig(active);
}

%end

%hook DrawRootViewController

/// Log the recovered drawing close handler so button behavior can be verified at runtime.
- (void)closeTapped {
    SSHHLog(@"DrawRootViewController closeTapped intercepted self=%@", SSHHDescribeObject(self));
    %orig;
}

%end

%hook SettingViewController

/// Log the recovered live-mode switch action and the UISwitch state passed by our helper or the original UI.
- (void)liveSwitchChanged:(UISwitch *)sender {
    SSHHLog(@"SettingViewController liveSwitchChanged: intercepted self=%@ sender=%@ on=%@", SSHHDescribeObject(self), SSHHDescribeObject(sender), sender.on ? @"YES" : @"NO");
    %orig;
}

/// Log live-mode refreshes to confirm the defaults/notification path is being consumed.
- (void)refreshLiveMode {
    SSHHLog(@"SettingViewController refreshLiveMode intercepted self=%@", SSHHDescribeObject(self));
    %orig;
}

%end

/// Constructor used for a narrow runtime sanity log.
%ctor {
    NSBundle *mainBundle = NSBundle.mainBundle;
    SSHHLog(@"Loaded bundleID=%@ executable=%@ process=%@", mainBundle.bundleIdentifier, mainBundle.executablePath.lastPathComponent, NSProcessInfo.processInfo.processName);
    int closeLogToken = 0;
    notify_register_dispatch(SSHHCloseLogNotificationName.UTF8String, &closeLogToken, dispatch_get_main_queue(), ^(int token) {
        /// Critical logic: close the floating log window in whichever injected runtime owns that high-level UIWindow.
        SSHHHideLogWindowsFromRuntime("darwinNotification");
    });
    SSHHDumpTargetClass();
}
