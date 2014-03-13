//
//  CSecurityScanController.h
//  XSecurity
//
//  Created by Tokuji Akamine on 1/21/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Main.h"
#import "CVulnController.h"
#import "CSecurityGuideWindowController.h"

@interface CSecurityScanController : NSObject  <DVTTextAnnotationDelegate, DVTMessageBubbleAnnotationDelegate> {
    
@private
    CVulnController *m_vulnController;
}

@property (atomic, assign) BOOL activationStatus;
@property (nonatomic,retain) CSecurityGuideWindowController *viewClickerController;

+ (id)sharedCenter;
- (void)initVulnController;
- (void)doScan:(IDESourceCodeDocument *)document;
- (void)removeAnnotations;

@end
