//
//  CSensitiveInfoKeywordsEx.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/31/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CSensitiveInfoKeywords.h"
#import "CKeywordVuln.h"
#import "CLog.h"
//////////////////////////////////////////////////////////////////////////////////////

@implementation CSensitiveInfoKeywords

- (id) init
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_aRegKeywords = nil ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

// aszKeywords is just a list of keywords
- (id) initWithKeywords: (NSArray *) aszKeywords
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_aRegKeywords = [[NSMutableArray alloc] init] ;
        
        NSError *err = nil ;
        
        for ( NSString *szKeyword in aszKeywords )
        {
            // Don't make it prefixed with the default word start look-ahead
            NSRegularExpression *regEx = [ NSRegularExpression regularExpressionWithPattern: [ CKeywordVuln ensure1stGroupOnPattern: szKeyword szPrefix: @""] options: 0 error: &err ] ;
            
            if ( !regEx || err )
            {
                [CLog xlogv: @"Error creating regular expression @%@", szKeyword] ;
                [CLog xlogv: @"Reason: %@", [err localizedDescription] ] ;
                continue ;
            }
            
            [ m_aRegKeywords addObject: regEx ] ;
        }
        
        // No need to retain m_aRegKeywords coz it's being preserved by default in alloc/init combination.
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_aRegKeywords release], m_aRegKeywords = nil ;
    
    [super dealloc] ;
}


// Outputs similar to the following, but not really optimizing all simple
// patterns to form a tight pattern to represent the entire list
// ((pass((w(or|)d)|)|(us(e|)r((name|id)|)))
- (NSString *) getCombinedPatterns
{
    NSString *szRet = nil ;
    
    do
    {
        NSMutableString *szPatterns = nil ;
        NSMutableArray *aRegKeywords = [self getKeywords] ;
        
        if ( ![aRegKeywords count] )
        {
            break ;
        }
        
        // No more parenthesis here because it is already made in initWithKeywords
        szPatterns = [ NSMutableString stringWithFormat: @"(%@", [aRegKeywords[0] pattern] ] ;
        
        NSInteger iCount = [aRegKeywords count] ;
        NSInteger iCtr = 1 ;
        
        for ( ; iCtr < iCount; iCtr++ )
        {
            [ szPatterns appendFormat: @"|%@", [aRegKeywords[iCtr] pattern] ] ;
        }
        
        [szPatterns appendString: @")"] ;
        
        szRet = [ NSString stringWithString: szPatterns ] ;
        
        // szRet is not allocated by this method thus no need to put autorelease
    } while ( _PASSING_ ) ;
    
    return szRet ;
}

//TODO: Upgrade into a property.
- (NSMutableArray *) getKeywords
{
    return m_aRegKeywords ;
}

- (void) setKeywords: (NSMutableArray *) aRegKeywords
{
    if ( m_aRegKeywords )
    {
        [m_aRegKeywords release] ;
    }
    
    m_aRegKeywords = aRegKeywords ;
    [m_aRegKeywords retain] ;
}

//TODO: Consider returning a string instead of a bool, to determine the
//      cause of the detection.
- (BOOL) isKeywordSensitive: (NSString *) szKeyword
{
    BOOL bRet = FALSE ;
    
    do
    {
        if ( !szKeyword )
        {
            break ;
        }
        
        NSMutableArray *aRegKeywords = [self getKeywords] ;
        
        if ( !aRegKeywords )
        {
            break ;
        }
        
        for ( NSRegularExpression *regEx in aRegKeywords )
        {
            NSRange rangeFirst = [ regEx rangeOfFirstMatchInString: szKeyword options: 0 range: NSMakeRange( 0, [szKeyword length] ) ] ;
            
            if ( !NSEqualRanges( rangeFirst, NSMakeRange(NSNotFound, 0) ) )
            {
                bRet = TRUE ;
                break ;
            }
        }
        
    } while ( _PASSING_ ) ;
    
    return bRet ;
}

@end
