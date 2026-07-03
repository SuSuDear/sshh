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

/// Primary file log path under a stable mobile-owned directory that survives jbroot path changes.
static NSString * const SSHHPrimaryLogPath = @"/var/mobile/SuSu/sshh.log";

/// Fallback path used if the sandbox cannot write to the workspace path.
static NSString * const SSHHFallbackLogPath = @"/tmp/sshh.log";

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

/// Retained top-level window so diagnostic controls stay visible without covering the HUD.
static UIWindow *SSHHHUDOverlayWindow;

/// Forward declaration for the passthrough window that only captures touches on real controls.
@interface SSHHPassthroughWindow : UIWindow
@end

/// Forward declarations used by the overlay button target implementation.
static void SSHHTryLaunchHUDFromController(UIViewController *controller);
static void SSHHTryCloseDrawingFromController(UIViewController *controller);
static void SSHHTryToggleLiveModeFromController(UIViewController *controller);
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
    SSHHTryLaunchHUDFromController(self.controller ?: SSHHFindVisibleWelcomeController());
    // Critical logic: after launching HUD, hide the start button so it cannot block HUD drag/tap gestures.
    SSHHSetOverlayStartButtonHidden(YES);
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
            SSHHLog(@"runtime candidate window %@ root=%@", SSHHDescribeObject(window), SSHHDescribeObject(window.rootViewController));
            SSHHCollectControllers(window.rootViewController, candidates);
        }
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

    BOOL nextEnabled = ![NSUserDefaults.standardUserDefaults boolForKey:@"live_key"];
    [NSUserDefaults.standardUserDefaults setBool:nextEnabled forKey:@"live_key"];
    [NSUserDefaults.standardUserDefaults synchronize];
    SSHHLog(@"live mode defaults live_key=%@", nextEnabled ? @"YES" : @"NO");

    UISwitch *senderSwitch = [UISwitch new];
    senderSwitch.on = nextEnabled;
    NSArray *candidates = SSHHCollectRuntimeCandidates(controller);
    NSUInteger switchInvoked = SSHHInvokeKnownObjectAction(candidates, @"liveSwitchChanged:", senderSwitch, @"live mode");
    NSUInteger refreshInvoked = SSHHInvokeKnownNoArgAction(candidates, @"refreshLiveMode", @"live mode");

    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSString *notificationName = [NSString stringWithFormat:@"%@.notification.hud.live-mode-changed", bundleID];
    // Critical logic: notify the HUD process path recovered from Calculator strings without relying on UI reachability.
    notify_post(notificationName.UTF8String);
    SSHHLog(@"live mode notified name=%@ switchInvoked=%lu refreshInvoked=%lu", notificationName, (unsigned long)switchInvoked, (unsigned long)refreshInvoked);
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
        button.frame = CGRectMake(24.0, 120.0, 160.0, 44.0);
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

    CGRect overlayFrame = CGRectMake(24.0, 80.0, 160.0, 148.0);
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
    overlayButton.frame = CGRectMake(0.0, 0.0, overlayFrame.size.width, 44.0);
    overlayButton.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleBottomMargin;
    overlayButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.35 blue:1.0 alpha:0.85];
    overlayButton.layer.cornerRadius = 10.0;
    [overlayButton setTitle:@"启动HUD" forState:UIControlStateNormal];
    [overlayButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    UIButton *closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    closeButton.frame = CGRectMake(0.0, 52.0, overlayFrame.size.width, 44.0);
    closeButton.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    closeButton.backgroundColor = [UIColor colorWithRed:0.8 green:0.15 blue:0.15 alpha:0.85];
    closeButton.layer.cornerRadius = 10.0;
    [closeButton setTitle:@"关闭绘制" forState:UIControlStateNormal];
    [closeButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    UIButton *liveButton = [UIButton buttonWithType:UIButtonTypeSystem];
    liveButton.frame = CGRectMake(0.0, 104.0, overlayFrame.size.width, 44.0);
    liveButton.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    liveButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.6 blue:0.25 alpha:0.85];
    liveButton.layer.cornerRadius = 10.0;
    [liveButton setTitle:@"直播模式" forState:UIControlStateNormal];
    [liveButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];

    SSHHHUDButtonTarget *overlayTarget = [SSHHHUDButtonTarget new];
    overlayTarget.controller = controller;
    [overlayButton addTarget:overlayTarget action:@selector(sshh_launchHUDButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [closeButton addTarget:overlayTarget action:@selector(sshh_closeDrawingButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [liveButton addTarget:overlayTarget action:@selector(sshh_toggleLiveModeButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [rootController.view addSubview:overlayButton];
    [rootController.view addSubview:closeButton];
    [rootController.view addSubview:liveButton];
    objc_setAssociatedObject(rootController, &SSHHHUDOverlayTargetKey, overlayTarget, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    SSHHHUDOverlayWindow = overlayWindow;
    SSHHLog(@"HUD top overlay buttons installed window=%@ startButton=%@ closeButton=%@ liveButton=%@ scene=%@", SSHHDescribeObject(overlayWindow), SSHHDescribeObject(overlayButton), SSHHDescribeObject(closeButton), SSHHDescribeObject(liveButton), SSHHDescribeObject(activeWindowScene));
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

    if ([title isEqualToString:SSHHVerificationTitle]) {
        SSHHLog(@"suppressing verification alert and retrying ToHome:YES");
        UIViewController *welcomeController = SSHHFindWelcomeControllerFrom(self) ?: SSHHFindVisibleWelcomeController();
        SSHHScheduleEnterHome(welcomeController, "presentVerificationAlert");
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
}

/// Log floating-ball display to determine whether manual invocation reaches visible UI.
- (void)showFloatingBall {
    SSHHLog(@"ViewController showFloatingBall intercepted self=%@", SSHHDescribeObject(self));
    %orig;
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
    SSHHDumpTargetClass();
}
