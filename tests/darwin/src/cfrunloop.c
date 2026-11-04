// CoreFoundation's run loop: a repeating timer that stops the loop on its
// third firing, and a block performed on the loop.

#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

static int fired, performed;

static void tick(CFRunLoopTimerRef timer, void *info) {
    if (++fired == 3) {
        CFRunLoopStop(CFRunLoopGetCurrent());
    }
}

int main(void) {
    CFRunLoopRef loop = CFRunLoopGetCurrent();
    CFRunLoopTimerRef t = CFRunLoopTimerCreate(NULL, CFAbsoluteTimeGetCurrent() + 0.01, 0.01, 0, 0, tick, NULL);
    CFRunLoopAddTimer(loop, t, kCFRunLoopDefaultMode);
    CFRunLoopPerformBlock(loop, kCFRunLoopDefaultMode, ^{
        performed = 1;
    });
    CFRunLoopRun();
    CFStringRef s = CFStringCreateWithFormat(NULL, NULL, CFSTR("cfrunloop %d %d"), fired, performed);
    char buf[64];
    CFStringGetCString(s, buf, sizeof buf, kCFStringEncodingUTF8);
    puts(buf);
    return fired == 3 && performed ? 0 : 1;
}
