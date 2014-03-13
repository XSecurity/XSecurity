//
//  QuickHelpController.h
//  XSecurity
//
//  Created by Tokuji Akamine on 12/10/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import "CSecurityGuide.h"

@interface CQuickHelpController : NSObject
{
@private
    NSDictionary *m_dicSecurityGuides;
}

@property (nonatomic, assign) BOOL activationStatus;
@property (nonatomic, assign) BOOL bIsUtilityAreaVisible;
@property (nonatomic, retain) WebView *webview;

+ (id)sharedCenter;
- (void)addSecurityGuide:(CSecurityGuide *)secGuide;
- (CSecurityGuide *)detect:(NSString *)string;

@end
