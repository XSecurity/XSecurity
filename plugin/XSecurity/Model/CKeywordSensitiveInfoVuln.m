//
//  CKeywordSensitiveInfo.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/14/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CKeywordSensitiveInfoVuln.h"
#import "CInstance.h"
#import "XSecDefs.h"
#import "CLog.h"

// Not really sure if this is the right way to do it but I just decided that only the
// controller should know the serialization of classes, e.g. reading from plist file.
#import "CVulnController.h"

@interface CKeywordSensitiveInfoVuln (Protected)

-(NSMutableArray *) generatePatterns ;
- (void)            setRegExpressions: (NSArray *) aRegExps ;
- (NSArray *)       getRegExpressions ;
- (NSArray *)       toExpressions:(NSMutableArray *) aszPatterns option: (NSRegularExpressionOptions) option ;

- (BOOL) addSpaceToPatterns: (NSMutableArray *)aszPatterns ;
- (BOOL) splitArg: (NSString *)szArg toParam: (NSString **)pszParam toValue: (NSString **)pszValue ;
- (NSMutableArray *) applyToPatterns: (NSMutableArray *)aszPatterns theParam: (NSString *)szParam withValue: (NSString *) szValue ;

- (NSMutableArray *) applyToPatterns: (NSMutableArray *)aszPatterns theParam: (NSString *)szParam withValue: (NSString *) szValue returnOnlyReplaced: (BOOL) bReturnOnlyReplaced includeCaster: (BOOL) bIncludeCaster ;
@end

@implementation CKeywordSensitiveInfoVuln

// Default constructor
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

//NOTE: [METHODS] and [FUNCTIONS] may not necessarily be inclosed with parenthesis
- (NSArray *) initInstancesFromDictionary: (NSDictionary *)dicInstances
{
    NSArray *aRet = nil ;
    
//    [CLog xlogv: @"Entering %@", __FUNCTION__] ;
    
    do
    {
        NSMutableArray *aInstances = [ [[NSMutableArray alloc] init] autorelease] ;
        
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
            
            CKeywordSensitiveInstance *objInstance = [ [CKeywordSensitiveInstance alloc] initWithClass: szKey withMethods: [dicClassName objectForKey: @"Methods"]  withArgs: [dicClassName objectForKey: @"Args" ] withFunctions: [dicClassName objectForKey: @"Functions"] ] ;
            
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

// Overriden to change the default option for this class
- (NSArray *) toExpressions:(NSMutableArray *) aszPatterns
{
//    [CLog xlogv: @"Entering %@", __FUNCTION__] ;

    // NOTE:
    // As far as I can remember I need to override this function to force NSRegularExpressionDotMatchesLineSeparators.
    // The reason is as far as I can remember is it needs to do a backreference for variable assignment,
    // without NSRegularExpressionDotMatchesLineSeparators backreference would be impossible
    
    // The back reference helped fix the false-positive for the meantime.
    return [self toExpressions: aszPatterns option: NSRegularExpressionCaseInsensitive | NSRegularExpressionDotMatchesLineSeparators] ;
}

// Overriden to add [FUNCTIONS] before processing the instance
- (BOOL) onPreProcessPatterns: (NSMutableArray *)aszPatterns onInstance: (CInstance *)objInstance
{
//    [CLog xlogv: @"Entering %@", __FUNCTION__] ;
    // Just add functions
    [ aszPatterns addObjectsFromArray: [((CKeywordSensitiveInstance *)objInstance) getFunctions] ] ;
    
    return TRUE ;
}

// Sample input:
// [FUNCTION] = NSLog\(.*?%@.*?\)\s*?;
// [METHOD]   = setObject\s*?:\s*?.*?%@.*?forKey\s*?:
//            = setObject\s*?:.*?:forKey\s*?:\s*?.*?%@.*?
// Overridden to insert patterns of the sensitive information
- (BOOL) onPreConvertPatternsToRegEx: (NSMutableArray *)aszPatterns
{
//    [CLog xlogv: @"Entering %@", __FUNCTION__] ;
    BOOL bRet = FALSE ;
    
    CSensitiveInfoKeywords *objInfoKeywords = [CVulnController createSensitiveInfoKeywordsObject] ;
    
    do
    {
        if ( !objInfoKeywords )
        {
            break ;
        }
        
        NSString *szSensitiveInfoPattern = [ objInfoKeywords getCombinedPatterns ] ;
        
        if ( !szSensitiveInfoPattern )
        {
            break ;
        }
        
        NSUInteger iCount = [aszPatterns count] ;
        
        for ( NSUInteger iCtr = 0; iCtr <  iCount; iCtr++ )
        {
            // This is a bit cryptic but each pattern should include a literal %@ in order to include the pattern
            // that will mark the match as sensitive
            [ aszPatterns replaceObjectAtIndex: iCtr withObject: [NSString stringWithFormat: aszPatterns[iCtr], szSensitiveInfoPattern] ] ;
        }
        
        bRet = TRUE ;
    } while ( _PASSING_ ) ;
    
    return bRet ;
}

// Main difference in this version of generatePatterns is it will take one
// [ARG] replace it to [METHODS] making unique position of [ARG] in [METHODS]
// Sample Input:
// [METHOD] = setObject:forKey:
// [ARGS]   = setObject:.*?%@.*?
//          = forKey:.*?%@.*?
//
// Sample Output:
// [METHOD]   = setObject\s*?:\s*?.*?%@.*?forKey\s*?:.*?
//            = setObject\s*?:.*?:forKey\s*?:\s*?.*?%@.*?
//
-(NSMutableArray *) generatePatterns
{
//    [CLog xlogv: @"Entering %@", __FUNCTION__] ;
    // String patterns
    NSMutableArray *aAllPatterns = [ [[NSMutableArray alloc] init] autorelease ] ;
    
    do
    {
        // Out of memory?
        if ( !aAllPatterns )
        {
            break ;
        }
        
        NSArray *aInstances = [self getInstances] ;
        
        if ( !aInstances )
        {
            break ;
        }
        
        for ( CKeywordSensitiveInstance *objInstance in aInstances )
        {
            // Array of strings, by default it points to the [METHODS]
            NSMutableArray  *aPatterns = [ [[NSMutableArray alloc] init] autorelease ] ;
            NSArray *aArgs = [objInstance getArgs] ;
            
            for ( NSString *szArg in aArgs )
            {
                NSMutableArray  *aszMethods = [ NSMutableArray arrayWithArray: [objInstance getMethods] ] ;
                
                // There should be methods to apply the args
                if ( !aszMethods )
                {
                    break ;
                }
                
                NSString *szParam = nil ;
                NSString *szValue = nil ;
                
                //NOTE: This can be done with one big loop through the patterns and assumed to be much
                //      faster in performance but I opted to make this more readable than efficient.
                //      Should there be a performance issue these should be the ones that should be refactored.
                
                // Try to split the argument, just calling it argument for argument's sake, doesn't make sense ;-)
                if ( ![self splitArg: szArg toParam: &szParam toValue: &szValue] )
                {
                    continue ;
                }
                
                // Attach values to corresponding parameters, and return only those has been attached at
                aszMethods = [self applyToPatterns: aszMethods theParam: szParam withValue: szValue returnOnlyReplaced: TRUE includeCaster: FALSE] ;
                
                if ( !aszMethods )
                {
                    continue ;
                }

                [aPatterns addObjectsFromArray: aszMethods] ;
            }
            
            // Should be done only once
            // Attach space recognition in between parameters
            if ( ![self addSpaceToPatterns: aPatterns] )
            {
                continue ; // There must be something wrong about it to fail
            }
            
            // Add [FUNCTIONS] in the list
            [ aPatterns addObjectsFromArray: [objInstance getFunctions] ] ;
            
            [aAllPatterns addObjectsFromArray: aPatterns] ;
        }
    } while ( _PASSING_ ) ;
    
    return aAllPatterns ;
}



@end
