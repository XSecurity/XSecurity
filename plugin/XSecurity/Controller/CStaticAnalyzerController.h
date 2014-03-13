//
//  CStaticAnalyzerController.h
//  XSecurity
//
//  Created by Tokuji Akamine on 1/22/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
@class PBXNativeTarget;

@interface CStaticAnalyzerController : NSObject {
    
@private
    PBXNativeTarget *tmpPbxTarget;
    void *key;
    NSString *tmpBuildString;
}

@property (atomic, assign) BOOL bRunning;

+ (id)sharedCenter;
- (void)analyze;
- (void)finishAnalysis;
@end
