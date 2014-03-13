//
//  CKeywordCalleeVuln.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/12/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CKeywordCalleeVuln.h"
#import "CInstance.h"
#import "XSecDefs.h"

// Virtually call protected method (Protected) here is just arbitrary value
@interface CKeywordCalleeVuln (Protected)
- (void)      setRegExpressions: (NSArray *) aRegExps ;
- (BOOL)      addSpaceToPatterns: (NSMutableArray *)aszPatterns ;
- (NSArray *) toExpressions:(NSMutableArray *) aszPatterns option: (NSRegularExpressionOptions)option ;
@end


//TODO: - Implement method below and fix those errors
//      - Add logic to consider inside @implementation XXX, where XXX is the class name or the instance name
//      - Also add logic to get the entire method, though it is assumed that Red is going to give me the entire method at a time,
//        but that should not rely on that because that may change in time.
//      - Add new model of CInstance
@implementation CKeywordCalleeVuln

// Default Constructor
- (id) init
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

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
            
            CKeywordCalleeInstance *objInstance = [ [CKeywordCalleeInstance alloc] initWithClass: szKey withDicMethods: [dicClassName objectForKey: @"Methods"]  ] ;
            
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

// SAMPLE INPUT: (should be tight, meaning without spaces otherwise will be stripped)
// +(BOOL)allowsAnyHTTPSCertificateForHost:

// SAMPLE OUTPUT:
// \+\s*?.*?\(\s*?BOOL\s*?\)\s*?allowsAnyHTTPSCertificateForHost\s*?:.*?
// \+\s*?.*?\(\s*?(BOOL)\s*?\)\s*?allowsAnyHTTPSCertificateForHost\s*?:.*?

// BREAKDOWN:
// \+\s*?.*?
// \(\s*?BOOL\s*?\)
// \s*?allowsAnyHTTPSCertificateForHost
// \s*?:.*?

// SAMPLE INPUT: (should be tight, meaning without spaces otherwise will be stripped)
// +(BOOL)allowsAnyHTTPSCertificateForHost:

// SAMPLE OUTPUT:
// \+\s*?.*?\(\s*?BOOL\s*?\)\s*?allowsAnyHTTPSCertificateForHost\s*?:.*?
// \+\s*?.*?\(\s*?(BOOL)\s*?\)\s*?allowsAnyHTTPSCertificateForHost\s*?:.*?

// BREAKDOWN:
// \+\s*?.*?
// \(\s*?BOOL\s*?\)
// \s*?allowsAnyHTTPSCertificateForHost
// \s*?:.*?

- (NSString *)decorateMethod: (NSString *)szMethod
{
    NSString *szRet = nil ;
    
    do
    {
        NSError *err = nil ;
        
        NSRegularExpression *regExPreamble = [NSRegularExpression regularExpressionWithPattern: @"(\\+|\\-)\\s*?\\(\\s*?(.*?)\\s*?\\)(.*?)$" options: 0 error: &err ] ;
        
        if ( !regExPreamble || err )
        {
            break ;
        }
        
        //\\s*?(.*?)\\s*?(:)
        
        NSTextCheckingResult *matchTxt = [regExPreamble firstMatchInString: szMethod options: 0 range: NSMakeRange(0, [szMethod length]) ] ;
        
        // This process is failing...
        if ( !matchTxt )
        {
            break ;
        }
        
        // Long method but needs to know if this is failing anyway.
        // Class or Instance method (+/-)
        NSString *szMethodMarker = nil, *szReturnType = nil ;
        NSString **aszPreamble[] = { &szMethodMarker, &szReturnType } ;
        BOOL bErroOccurred = FALSE ;
        
        int iPreambleIdx = 0 ;
        // Fill-in aszParts but actually, indirectly filling in the rest of the variables above.
        for ( ; iPreambleIdx < _countof( aszPreamble ); iPreambleIdx++ )
        {
            *(aszPreamble[ iPreambleIdx ]) = [ szMethod substringWithRange: [matchTxt rangeAtIndex: iPreambleIdx + 1] ] ;
            
            // Empty part
            if ( ![ (*(aszPreamble[ iPreambleIdx ])) length ] )
            {
                bErroOccurred = TRUE ;
                break ;
            }
        }
        
        if ( bErroOccurred )
        {
            break ;
        }
        
        // Remaining parts starting from method name
        NSString *szPayload = [ szMethod substringWithRange: [matchTxt rangeAtIndex: iPreambleIdx + 1] ] ;
        
        if ( ![szPayload length] )
        {
            break ;
        }
        
        // This includes method name, this might include an empty element
        NSMutableArray *aszArgs = [NSMutableArray arrayWithArray: [szPayload componentsSeparatedByString:@":"]] ;

        if ( ![aszArgs count])
        {
            break ;
        }
        
        // Check if the last element is empty
        if ( ![ aszArgs[[aszArgs count] - 1] length ] )
        {
            [ aszArgs removeLastObject ] ;
        }
       
        if ( ![aszArgs count] )
        {
            break ;
        }
        
        for ( int iCtr = 0; iCtr < [aszArgs count];  iCtr++)
        {
            aszArgs[ iCtr ] = [NSString stringWithFormat: @"\\s*?%@\\s*?:.*?", aszArgs[ iCtr ]] ;
        }
        
        NSMutableString *szPreamble = [ NSMutableString stringWithFormat:
                 @"\\%@\\s*?.*?"
                 @"\\(\\s*?%@\\s*?\\)"
                 , szMethodMarker
                 , [ NSRegularExpression escapedPatternForString: szReturnType ]
                 ] ;
       
        for ( int iCtr = 0 ; iCtr < [aszArgs count]; iCtr++ )
        {
            [szPreamble appendString: aszArgs[iCtr]] ;
        }
        
        szRet = [NSString stringWithString: szPreamble] ;
    } while ( _PASSING_ ) ;
    
    return szRet ;
}


// SAMPLE INPUT:
//  Class :  NSURLRequest
//  Method:  +(BOOL)allowsAnyHTTPSCertificateForHost:
//  Keyword: return\s*?(YES|TRUE|true|1)\s*?;

// SAMPLE OUTPUT:
//  @\s*?implementation\s*?NSURLRequest\s*?.*?\+\s*?.*?\(\s*?BOOL\s*?\)\s*?allowsAnyHTTPSCertificateForHost\s*?:.*?\{.*?(return\s*?(YES|TRUE|true|1)\s*?;).*?\}\s*?@\s*?end

// with S option

// BREAKDOWN:
//  @\s*?implementation\s*?
//  NSURLRequest
//  \s*?.*?
//  \+\s*?.*?\(\s*?BOOL\s*?\)\s*?allowsAnyHTTPSCertificateForHost\s*?:.*?
//  \{.*?
//  (return\s*?(YES|TRUE|true|1)\s*?;)
//  .*?\}\s*?@\s*?end

// RULES in creating entries in the plist file
// - Methods return value should include escapes in regEx like * should be \*

// Helper method, won't check for valid parameters
- (NSString *)createPatternFromClass: (NSString *)szClassName withMethod: (NSString *)szMethod withKeyword: (NSString *)szKeyword
{
    NSString *szPattern = [NSString stringWithFormat:
                           @"@\\s*?implementation\\s*?"
                           @"%@"
                           @"\\s*?.*?"
                           @"%@"
                           @"\\{.*?"
                           @"(%@)"
                           @".*?\\}\\s*?@\\s*?end"
                           , szClassName
                           , [self decorateMethod: szMethod]
                           , szKeyword
                           ] ;
    
    return szPattern ;
}

- (NSArray *) generateExpressions
{
    NSArray *aRet = [self getRegExpressions] ;
    
    do
    {
        // Already made one earlier?
        if ( aRet )
        {
            break ;
        }
        
        NSArray *aInstances = [self getInstances] ;
        
        if ( !aInstances )
        {
            break ;
        }
        
        // String patterns
        NSMutableArray *aAllPatterns = [ [NSMutableArray alloc] init ] ;
        
        // Out of memory?
        if ( !aAllPatterns )
        {
            break ;
        }
        
        for ( CKeywordCalleeInstance *objInstance in aInstances )
        {
            // Array of strings
            NSMutableArray  *aPatterns = [ [NSMutableArray alloc] init ] ;
            
            NSString     *szClassName = [objInstance getClass] ;
            NSDictionary *dicMethods  = [objInstance getDicMethods] ;
            
            if ( !dicMethods )
            {
                continue ;
            }
            
            // For each method
            for ( NSString *szMethodKey in dicMethods )
            {
                NSDictionary *dicOneMethod = [dicMethods objectForKey: szMethodKey] ;
                
                if ( !dicOneMethod )
                {
                    continue ;
                }
                
                NSArray *aszKeywords = [dicOneMethod objectForKey: @"Keywords"] ;
                
                // For each keyword
                for ( NSString *szKeyword in aszKeywords )
                {
                    NSString *szPattern = [self createPatternFromClass: szClassName withMethod: szMethodKey withKeyword:szKeyword] ;
                    
                    if ( !szPattern )
                    {
                        continue ;
                    }
                    
                    [aPatterns addObject: szPattern] ;
                }
            }
            
            // This should not be happening but just in case
            // The assumption is there should be at least one METHOD
            if ( ![aPatterns count] )
            {
                continue ;
            }
            
            [aAllPatterns addObjectsFromArray: aPatterns] ;
            
        }
        
        if ( ![aAllPatterns count] )
        {
            break ;
        }
        
        aRet = [ NSArray arrayWithArray: [self toExpressions: aAllPatterns option: NSRegularExpressionDotMatchesLineSeparators ] ] ;
        
        if ( !aRet || ![aRet count] )
        {
            break ;
        }
        
        [self setRegExpressions: aRet] ;
        
    } while ( _PASSING_ ) ;
    
    return aRet ;
}

@end
