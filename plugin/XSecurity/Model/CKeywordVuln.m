//
//  CKeywordVuln.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CKeywordVuln.h"
#import "CInstance.h"

//////////////////////////////////////////////////////////////////////////////////////

@implementation CKeywordVuln

+ (NSString *) ensure1stGroupOnPattern: (NSString *)szPattern szPrefix: (NSString *)szPrefix
{
    return [ NSString stringWithFormat: @"%@(%@)", szPrefix, szPattern ] ;
}


+ (NSString *) ensure1stGroupOnPattern: (NSString *)szPattern
{
    return [ NSString stringWithFormat: @"(?:\\b)(%@)", szPattern ] ;
}

// Default implementation for all CKeywordVuln's subclasses
- (NSArray *) initInstancesFromDictionary: (NSDictionary *)dicInstances
{
    NSArray *aRet = nil ;
    
    do
    {
        NSMutableArray *aInstances = [ [[NSMutableArray alloc] init] autorelease ] ;
        
        if ( !dicInstances || !aInstances )
        {
            break ;
        }
        
        for ( NSString *szKey in dicInstances )
        {
            NSDictionary *dicClassName = [dicInstances objectForKey: szKey] ;
            
            if ( !dicClassName )
            {
                continue ;
            }
            
            CKeywordInstance *objInstance = [ [CKeywordInstance alloc] initWithClass: szKey withMethods: [dicClassName objectForKey: @"Methods"]  withArgs: [dicClassName objectForKey: @"Args" ] ] ;
            
            if ( !objInstance )
            {
                continue ;
            }
            
            [aInstances addObject: objInstance] ;
            [objInstance release] ;
        }
        
        if ( ![aInstances count] )
        {
            break ;
        }
        
        aRet = [NSArray arrayWithArray: aInstances] ;
        
    } while ( _PASSING_ ) ;
    
    return aRet ;
}

// Defaults to colon (:)
- (BOOL) addSpaceToPatterns: (NSMutableArray *)aszPatterns
{
    return [ self addSpaceToPatterns: aszPatterns szToken: @":" ] ;
}

//DONE: Make non-capturing group work, it does not work because it still captures the
//      leading spaces which should not be.
//      One idea would be using the array of matches and there should be 1 capturing group and
//      that should be group #1 aka \1
//      Consider this pattern: (?:\b)(setAllowsAnyHTTPSCertificate\s*:((\s*\(\s*)+|\s*)(YES|TRUE|true)((\s*\)\s*)+|\s*))
//      to match this case: URLRequest setAllowsAnyHTTPSCertificate:(YES ) forHost:[URL host]];

// Adds space recogintion to all colons(:), excluding the portion where the parameters has been applied
// Group 1 or 1st group is ensured here
- (BOOL) addSpaceToPatterns: (NSMutableArray *)aszPatterns szToken: (NSString *)szToken
{
    BOOL bRet = FALSE ;
    
    do
    {
        NSError *err ;
        NSString *szTokenPattern = [NSString stringWithFormat: @"%@([^\\(]|$)", szToken] ;
        
        NSRegularExpression *regEx = [NSRegularExpression regularExpressionWithPattern: szTokenPattern options:(NSRegularExpressionOptions) 0 error: &err] ;
        
//        NSRegularExpression *regEx = [NSRegularExpression regularExpressionWithPattern: @":([^\\(]|$)" options:(NSRegularExpressionOptions) 0 error: &err] ;
        
        szTokenPattern = [NSString stringWithFormat: @"\\\\s*%@\\\\s*.*?\\\\s*$1", szToken] ;
        
        for ( int iCtr = 0; iCtr < [aszPatterns count]; iCtr++ )
        {
            // Replace colon(:) (followed by neither ( nor ]) or (followed by $)
            NSString *szPattern = [ regEx stringByReplacingMatchesInString: aszPatterns[iCtr] options: (NSMatchingOptions)0 range: NSMakeRange(0, [aszPatterns[iCtr] length]) withTemplate: szTokenPattern ] ;

//          NSString *szPattern = [ regEx stringByReplacingMatchesInString: aszPatterns[iCtr] options: (NSMatchingOptions)0 range: NSMakeRange(0, [aszPatterns[iCtr] length]) withTemplate: @"\\\\s*:\\\\s*.*?\\\\s*$1" ] ;
            
            // This should be done last because the colon (:) in the non-capturing group will
            // be inserted with spaces through the line above
            aszPatterns[iCtr] = [CKeywordVuln ensure1stGroupOnPattern: szPattern] ;
        }
        
        bRet = TRUE ;
    } while ( _PASSING_ ) ;
    
    return bRet ;
}

- (BOOL) ensure1stGroupInPatterns: (NSMutableArray *)aszPatterns
{
    BOOL bRet = FALSE ;
    
    do
    {
        for ( int iCtr = 0; iCtr < [aszPatterns count]; iCtr++ )
        {
            aszPatterns[iCtr] = [ CKeywordVuln ensure1stGroupOnPattern: aszPatterns[iCtr] ] ;
        }
        
        bRet = TRUE ;
    } while ( _PASSING_ ) ;
    
    return bRet ;
}



@end // CKeywordVuln

