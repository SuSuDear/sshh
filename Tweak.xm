#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>

/// Lightweight runtime helper for the Calculator welcome controller.
/// The tweak intentionally avoids touching files on disk and only redirects the
/// in-memory welcome flow once the target controller is alive.
static NSString * const SSHHTargetControllerName = @"TSHWelcomeViewController";

/// Returns YES only for the expected welcome controller so hooks stay narrow.
static BOOL SSHHIsTargetWelcomeController(id object) {
    Class targetClass = NSClassFromString(SSHHTargetControllerName);
    return targetClass != Nil && object != nil && [object isKindOfClass:targetClass];
}

/// Calls a boolean setter safely when the target implements it.
/// This keeps the controller's own state consistent before entering Home.
static void SSHHSetBoolIfPossible(id object, SEL selector, BOOL value) {
    if (object != nil && [object respondsToSelector:selector]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(object, selector, value);
    }
}

/// Executes the final navigation primitive observed in the target binary.
/// Critical logic: pass YES to ToHome: so the original method takes the Home path.
static void SSHHForceEnterHomeNow(id controller, const char *reason) {
    if (!SSHHIsTargetWelcomeController(controller)) {
        return;
    }

    SEL toHomeSelector = NSSelectorFromString(@"ToHome:");
    if (![controller respondsToSelector:toHomeSelector]) {
        NSLog(@"[sshh] ToHome: is unavailable, reason=%s", reason ?: "unknown");
        return;
    }

    // Mark the welcome flow as already handled to avoid repeated animation/poll loops.
    SSHHSetBoolIfPossible(controller, NSSelectorFromString(@"setTsh_activationStarted:"), YES);
    SSHHSetBoolIfPossible(controller, NSSelectorFromString(@"setTsh_didEnterHome:"), YES);

    NSLog(@"[sshh] Forcing ToHome:YES, reason=%s", reason ?: "unknown");
    ((void (*)(id, SEL, BOOL))objc_msgSend)(controller, toHomeSelector, YES);
}

/// Schedules the navigation on the main queue after UIKit has had a chance to
/// finish layout/presentation. This avoids calling ToHome: too early from viewDidLoad.
static void SSHHScheduleEnterHome(id controller, const char *reason) {
    if (!SSHHIsTargetWelcomeController(controller)) {
        return;
    }

    __weak id weakController = controller;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.20 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        id strongController = weakController;
        SSHHForceEnterHomeNow(strongController, reason);
    });
}

%hook TSHWelcomeViewController

/// Preserve the original UI setup, then schedule the controlled transition.
- (void)viewDidLoad {
    %orig;
    SSHHScheduleEnterHome(self, "viewDidLoad");
}

/// viewDidAppear: is the most reliable point because the controller is on screen.
- (void)viewDidAppear:(BOOL)animated {
    %orig;
    SSHHScheduleEnterHome(self, "viewDidAppear");
}

/// Replace the activation poll/check with the already identified final transition.
- (void)tsh_checkActivationAndEnterHome {
    SSHHScheduleEnterHome(self, "tsh_checkActivationAndEnterHome");
}

%end

/// Constructor used only for a narrow runtime sanity log.
%ctor {
    NSLog(@"[sshh] Loaded for Calculator welcome flow");
}
