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

/// Primary file log path inside the plugin workspace requested by the operator.
static NSString * const SSHHPrimaryLogPath = @"/var/mobile/Containers/Shared/AppGroup/.jbroot-6622400836D9B053/var/mobile/SuSu/sshh/sshh.log";

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

%hook TSHWelcomeViewController

/// Preserve original setup, then log and schedule the controlled transition.
- (void)viewDidLoad {
    SSHHLog(@"TSHWelcomeViewController viewDidLoad self=%@", SSHHDescribeObject(self));
    %orig;
    SSHHScheduleEnterHome(self, "viewDidLoad");
}

/// viewDidAppear: is the most reliable point because the controller is on screen.
- (void)viewDidAppear:(BOOL)animated {
    SSHHLog(@"TSHWelcomeViewController viewDidAppear animated=%@ self=%@", animated ? @"YES" : @"NO", SSHHDescribeObject(self));
    %orig;
    SSHHScheduleEnterHome(self, "viewDidAppear");
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

/// Constructor used for a narrow runtime sanity log.
%ctor {
    NSBundle *mainBundle = NSBundle.mainBundle;
    SSHHLog(@"Loaded bundleID=%@ executable=%@ process=%@", mainBundle.bundleIdentifier, mainBundle.executablePath.lastPathComponent, NSProcessInfo.processInfo.processName);
    SSHHDumpTargetClass();
}
