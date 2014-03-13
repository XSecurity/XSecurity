//
//  Log.m
//  XSecurity
//
//  Created by Tokuji Akamine on 13/09/10.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CLog.h"

@implementation CLog


+(void)xlog:(NSString *)message
{
    NSLog(@"[XSecurity] %@", message);
}

+(void)xlog:(NSString *)message withObject:(id)object
{
    NSLog(@"[XSecurity] %@: %@", message, object);
}

+(void)xlog:(NSString *)message withPrettyFunc:(const char *)func
{
    NSLog(@"[XSecurity] %@ <%s>", message, func);
}

+(void)xlog:(NSString *)message withFile:(const char *)file withLine:(int)line
{
    NSLog(@"[XSecurity] %@ <%@:%d>", message, [[NSString stringWithUTF8String:file] lastPathComponent], line);
}

+(void)xlog:(NSString *)message withObject:(id)object withFile:(const char *)file withLine:(int)line
{
    NSLog(@"[XSecurity] %@: %@ <%@:%d>", message, object, [[NSString stringWithUTF8String:file] lastPathComponent], line);
}

+(void)xlogv:(NSString *)szFormat, ...
{
    va_list arg_list ;
    
    NSString *szActualLog = [NSString stringWithFormat: @"[XSecurity] %@", szFormat] ;
    
    va_start( arg_list, szFormat ) ;
    
    NSLogv( szActualLog, arg_list ) ;
    
    va_end( arg_list ) ;
}
@end