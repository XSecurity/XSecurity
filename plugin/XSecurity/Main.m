//
//  Main.m
//  XSecurity
//
//  Created by Tokuji Akamine on 8/23/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "Main.h"
#import "XSecDefs.h"

static Main *g_sharedPlugin = nil;

@implementation Main
+ (void)pluginDidLoad:(NSBundle *)plugin
{
    static dispatch_once_t onceToken ;
    
    dispatch_once(&onceToken, ^{
        g_sharedPlugin = [[self alloc] init];
    });
}

- (id) init
{
    if (self = [super init])
    {
        
        [[NSNotificationCenter defaultCenter] addObserver:self  selector:@selector(applicationDidFinishLaunching:) name:NSApplicationDidFinishLaunchingNotification object:nil];
        
    }
    return self;
}

// Called when application is launched
- (void) applicationDidFinishLaunching: (NSNotification*) notification
{
    [CLog xlog:@"The application is launched."];
    [CLog xlogv: @"Checkers: %@", _CHECKERS_] ;
    [self main];
}

- (void) main
{
    //[self setMenu];
    
    CXSecurityController *xSecurityController = [[CXSecurityController alloc] init];
    
    if ( xSecurityController == Nil )
    {
        [CLog xlog:@"xSecurityController is Nil"];
    }
    
    [xSecurityController addNotificationObserver];
    
}

- (void) dealloc
{
    // Stop getting the notification
    [[NSNotificationCenter defaultCenter] removeObserver:self] ;
    
    [super dealloc] ;
}


@end
