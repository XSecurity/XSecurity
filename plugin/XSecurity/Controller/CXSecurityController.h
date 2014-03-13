//
//  XSecurityController.h
//  XSecurity
//
//  Created by Tokuji Akamine on 12/10/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CMenuController.h"
#import <WebKit/WebKit.h>
#import "IDESourceEditor.h"
#import "CQuickHelpController.h"

@interface CXSecurityController : NSObject
+ (void)initialize ;
- (void)addNotificationObserver ;
@end
