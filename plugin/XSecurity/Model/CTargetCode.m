//
//  CTargetCode.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CLog.h"
#import "CTargetCode.h"


//////////////////////////////////////////////////////////////////////////////////////

@implementation CTargetCode
//@synthesize m_szData ; // Retain m_szData as it is, not _m_szData

-(id) init
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_szData = nil ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (id) initWithData: (NSString *) szData
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_szData = [NSMutableString stringWithString: szData], [m_szData retain]  ;
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (id) initWithFile: (NSString *) szFilePath
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        // nil or empty ?
        if ( [szFilePath length] == 0 )
        {
            break ;
        }
        
        NSError *errFile = nil ;
        
        m_szData = [NSMutableString stringWithContentsOfFile: szFilePath encoding: NSASCIIStringEncoding error: &errFile] ;
        
        if ( [m_szData length] == 0 )
        {
            [ CLog xlog: @"File opening error!" ] ;
            [ CLog xlog:[ errFile localizedDescription] ] ;
            self = nil ;
            break ;
        }
     
        [m_szData retain] ;
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_szData release], m_szData = nil ;
    
    [super dealloc] ;
}

- (NSMutableString *)getData
{
    return m_szData ;
}

- (NSString *)getDataAsString
{
    NSString *szRet = nil ;
    
    do
    {
        // Reference only, no need to release
        NSMutableString *szData = [self getData] ;

        if ( !szData )
        {
            break ;
        }
        
        szRet = [NSString stringWithString: szData] ;
        
    } while ( _PASSING_ ) ;
    
    return szRet ;
}

//
// NOTE: This expression is working with the commented source, knows it is inside a string literal
//
//    ^.*?(?<!@).*?(?<!")((/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|(//.*))
//    -------------------------------------------------------------
//    // comment test #1
//
//    /* oneline comment in multiline commenter */
//                  
//    /* multiline comment in
//     multi-line commenter */
//
//    // one line comment in oneline commenter
//
//    somestringxxx = @ "/*This is a comment inside a string xxx*/" ;
//    someStringToo = @"//This is a comment inside a string" ;
//
//    // /*
//    some_code() ;
//    // */D
//    -------------------------------------------------------------

// Does not detect the following, which is great!
//    somestringxxx = @ "/*This \" is a comment \"  \
//    inside a string xxx*/\
//    " ;

// This is failing but seems too much for now
//    somestringxxx = @ "/*This \" is a comment \"  \
//    /**/                                               <-- here exactly
//    inside a string xxx*/\
//    " ;
//    someStringToo = @"//This is a comment inside a string" ;


- (BOOL) maskCommentWith: (const unichar) chMask
{
    BOOL bRet = FALSE ;

    do
    {
        NSMutableString *szData = [self getData] ;
        NSString *szMask = [ [[NSString alloc] initWithCharacters: &chMask length: 1] autorelease ] ;
        
        if ( !szData || !szMask )
        {
            [CLog xlogv: @"!szData: %@ or !szChar: %@ fil: %@ ln: %d", szData, szMask, __FILE__, __LINE__ ] ;
            break ;
        }
        
        NSError *err = nil ;
        NSRegularExpression *regExpr = [NSRegularExpression regularExpressionWithPattern: @"^.*?(?<!@).*?(?<!\")((/\\*([^*]|[\r\n]|(\\*+([^*/]|[\r\n])))*\\*+/)|(//.*))" options: NSRegularExpressionAnchorsMatchLines  error: &err] ;
        
        if ( err )
        {
            [CLog xlogv: @"Some error with regex %@", [err localizedDescription] ] ;
            break ;
        }
        
        NSArray *aMatches = [ regExpr matchesInString: szData options: NSMatchingWithTransparentBounds range: NSMakeRange(0, [szData length] ) ] ;
        
        for ( NSTextCheckingResult *txtResult in aMatches )
        {
            NSRange txtRange = [txtResult rangeAtIndex: 1] ;
            
//            NSString *szMatch = [szData substringWithRange: txtRange] ;
//            [Log xlogv:@"pos: %d len: %0.2d %@", txtRange.location, txtRange.length, szMatch] ;

            [szData replaceOccurrencesOfString: @"." withString: szMask options:NSRegularExpressionSearch range: txtRange] ;
            //[szData replaceCharactersInRange: txtRange withString: szMask] ;
        }
        
//        [Log xlogv: @"------- SOURCE CODE------- \n\n%@", szData] ;
        
        bRet = TRUE ;
    } while ( _PASSING_ ) ;

    return bRet ;
}

- (id) copyWithZone:(NSZone *)zone
{
    CTargetCode *objNew = [ [CTargetCode alloc] init ] ;
    
    objNew -> m_szData = [m_szData mutableCopyWithZone: zone] ;
    
    return objNew ;
}

- (BOOL) log
{
    return TRUE ;
}
@end //CTargetCode



