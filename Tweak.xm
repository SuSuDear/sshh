#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>

/// Target controller identified from the Calculator binary.
/// Keeping this as a single constant makes all runtime checks narrow and auditable.
static NSString * const SSHHTargetControllerName = @"TSHWelcomeViewController";

/// Target verification alert title observed in the binary.
/// Used only for diagnostics and for dismissing the blocking activation prompt.
static NSString * const SSHHVerificationTitle = @"验证";

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
        NSLog(@"[sshh] set %@=%@ on %@", NSStringFromSelector(selector), value ? @"YES" : @"NO", SSHHDescribeObject(object));
        ((void (*)(id, SEL, BOOL))objc_msgSend)(object, selector, value);
    } else {
        NSLog(@"[sshh] skip setter %@ on %@", NSStringFromSelector(selector), SSHHDescribeObject(object));
    }
}

/// Executes the final navigation primitive observed in the target binary.
/// Critical logic: pass YES to ToHome: so the original method takes the Home path.
static void SSHHForceEnterHomeNow(id controller, const char *reason) {
    NSLog(@"[sshh] force request reason=%s controller=%@ targetClass=%@", reason ?: "unknown", SSHHDescribeObject(controller), NSClassFromString(SSHHTargetControllerName));

    if (!SSHHIsTargetWelcomeController(controller)) {
        NSLog(@"[sshh] force aborted: controller is not target welcome controller");
        return;
    }

    SEL toHomeSelector = NSSelectorFromString(@"ToHome:");
    if (![controller respondsToSelector:toHomeSelector]) {
        NSLog(@"[sshh] force aborted: ToHome: unavailable on %@", SSHHDescribeObject(controller));
        return;
    }

    // Mark the welcome flow as already handled to reduce repeated activation polling.
    SSHHSetBoolIfPossible(controller, NSSelectorFromString(@"setTsh_activationStarted:"), YES);
    SSHHSetBoolIfPossible(controller, NSSelectorFromString(@"setTsh_didEnterHome:"), YES);

    NSLog(@"[sshh] calling ToHome:YES reason=%s", reason ?: "unknown");
    ((void (*)(id, SEL, BOOL))objc_msgSend)(controller, toHomeSelector, YES);
}

/// Schedules navigation on the main queue after UIKit presentation/layout settles.
static void SSHHScheduleEnterHome(id controller, const char *reason) {
    NSLog(@"[sshh] schedule reason=%s controller=%@ isTarget=%@", reason ?: "unknown", SSHHDescribeObject(controller), SSHHIsTargetWelcomeController(controller) ? @"YES" : @"NO");

    __weak id weakController = controller;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.20 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        id strongController = weakController;
        SSHHForceEnterHomeNow(strongController, reason);
    });
}

/// Logs the available methods on the target class so we can confirm runtime names.
static void SSHHDumpTargetClass(void) {
    Class targetClass = NSClassFromString(SSHHTargetControllerName);
    NSLog(@"[sshh] target class lookup %@ -> %@", SSHHTargetControllerName, targetClass);
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
    NSLog(@"[sshh] target method count=%u methods=%@", methodCount, methodNames);
}

%hook TSHWelcomeViewController

/// Preserve original setup, then log and schedule the controlled transition.
- (void)viewDidLoad {
    NSLog(@"[sshh] TSHWelcomeViewController viewDidLoad self=%@", SSHHDescribeObject(self));
    %orig;
    SSHHScheduleEnterHome(self, "viewDidLoad");
}

/// viewDidAppear: is the most reliable point because the controller is on screen.
- (void)viewDidAppear:(BOOL)animated {
    NSLog(@"[sshh] TSHWelcomeViewController viewDidAppear animated=%@ self=%@", animated ? @"YES" : @"NO", SSHHDescribeObject(self));
    %orig;
    SSHHScheduleEnterHome(self, "viewDidAppear");
}

/// Replace the activation poll/check with the already identified final transition.
- (void)tsh_checkActivationAndEnterHome {
    NSLog(@"[sshh] tsh_checkActivationAndEnterHome intercepted self=%@", SSHHDescribeObject(self));
    SSHHScheduleEnterHome(self, "tsh_checkActivationAndEnterHome");
}

/// Log all calls into ToHome: and force the original implementation to receive YES.
/// This directly tests whether the final navigation branch is still being reached.
- (void)ToHome:(BOOL)enterHome {
    NSLog(@"[sshh] ToHome: intercepted originalArg=%@ self=%@ -> calling %%orig(YES)", enterHome ? @"YES" : @"NO", SSHHDescribeObject(self));
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
        NSLog(@"[sshh] present UIAlertController title=%@ message=%@ presenter=%@", title, message, SSHHDescribeObject(self));
    } else {
        NSLog(@"[sshh] present controller=%@ presenter=%@", SSHHDescribeObject(viewControllerToPresent), SSHHDescribeObject(self));
    }

    if ([title isEqualToString:SSHHVerificationTitle]) {
        NSLog(@"[sshh] suppressing verification alert and retrying ToHome:YES");
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
    NSLog(@"[sshh] UIAlertController viewDidAppear title=%@ message=%@ self=%@", self.title, self.message, SSHHDescribeObject(self));
    %orig;
}

%end

/// Constructor used for a narrow runtime sanity log.
%ctor {
    NSBundle *mainBundle = NSBundle.mainBundle;
    NSLog(@"[sshh] Loaded bundleID=%@ executable=%@ process=%@", mainBundle.bundleIdentifier, mainBundle.executablePath.lastPathComponent, NSProcessInfo.processInfo.processName);
    SSHHDumpTargetClass();
}
