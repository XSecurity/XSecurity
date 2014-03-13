//
//  Log.h
//  XSecurity
//
//  Created by Tokuji Akamine on 13/09/10.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CLog : NSObject
+(void)xlog:(NSString *)message;
+(void)xlog:(NSString *)message withObject:(id)object;
+(void)xlog:(NSString *)message withPrettyFunc:(const char *)func;
+(void)xlog:(NSString *)message withFile:(const char *)file withLine:(int)line;
+(void)xlog:(NSString *)message withObject:(id)object withFile:(const char *)file withLine:(int)line;
+(void)xlogv:(NSString *)szFormat, ... ;
@end
