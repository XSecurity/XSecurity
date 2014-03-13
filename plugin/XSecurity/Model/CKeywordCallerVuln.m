//
//  CKeywordCallerVuln.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/2/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import "CKeywordCallerVuln.h"
#import "CLog.h"
#import "XSecDefs.h"
#import "CInstance.h"

// NOTE: 

// Virtually call protected method (Protected) here is just arbitrary value
@interface CKeywordCallerVuln (Protected)
- (void)      setRegExpressions: (NSArray *) aRegExps ;
- (BOOL)      addSpaceToPatterns: (NSMutableArray *)aszPatterns ;
- (NSArray *) toExpressions:(NSMutableArray *) aszPatterns ;
@end

@implementation CKeywordCallerVuln

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



// NOTE: Subclasses should override this to generate their own expressions.
// Syntax = [METHOD] : [ARG], where ARG is [PARAM] : [VALUE]

// METHOD here refers to class methods and instance methods not just plain functions.

// As explained somewhere, matches [Args] with [Methods] to produce expressions/patterns
// It is ideal to auto generate the expression so that the user need not to think about
// RegEx. Although RegEx maybe used for cases where one parameter has multiple variants
// of possible values that needs to get detected. E.g. [NSURLRequest setAllowsAnyHTTPSCertificate]
// where the first parameter is either (YES|TRUE|true).

// Current assumption, on multiple ARGs for one METHOD are and(ed) with each other, meaning
// all of the ARGs should exist to be considered as a detection.
// e.g. METHOD = doAction:nextAction:
//      ARGs   = doAction:actionOne
//             = nextAction:actionTwo
//
// The and operation here is it should only detect when actionOne and actionTwo is used, otherwise
// it should not detect. On a single ARG then it is a must. ARGs and METHODs should not contain
// space in between colons(:)

// Sample input
// Methods:
//   initWithUser:password:persistence:
//   credentialWithUser:password:persistence:
//   credentialWithIdentity:certificates:persistence:
//
// Args:
//   persistence:NSURLCredentialPersistencePermanent
//

// Sample output
//
// (?:\s+)(initWithUser\s*:\s*.*?\s*password\s*:\s*.*?\s*persistence\s*:\s*.*?\s*NSURLCredentialPersistencePermanent)
// (?:\s+)(initWithIdentity\s*:\s*.*?\s*certificates\s*:\s*.*?\s*persistence\s*:\s*.*?\s*NSURLCredentialPersistencePermanent)
// (?:\s+)(credentialWithUser\s*:\s*.*?\s*password\s*:\s*.*?\s*persistence\s*:\s*.*?\s*NSURLCredentialPersistencePermanent)
// (?:\s+)(credentialWithIdentity\s*:\s*.*?\s*certificates\s*:\s*.*?\s*persistence\s*:\s*.*?\s*NSURLCredentialPersistencePermanent)
//
// (=(\s*|\s*\(.*?\)\s*)NSURLCredentialPersistencePermanent)
// (#define\s+.*?\s*NSURLCredentialPersistencePermanent)

// Limitation:
//   1.) Does not include the pattern which is directly passing or using a numeric literal representing an enum e.g. 1 for
//   NSURLCredentialPersistencePermanent.
//
//   2.) Does not support or(ed) ARGs to a METHOD. The opposite of the assumption above in the NOTE section.
//
//   Does not support the same PARAM
//   accross METHODs with different meanings.
//
//   e.g. METHODS = doAction:nextAction:
//                  doActionToo:nextAction:
//   Assuming that nextActions above have different meanings, then having ARGs like nextAction:myAction and nextAction:theirAction
//   is permitted. Although if nexAction has multiple values that should be detected then one use the following notation
//   instead: nextAction:(myAction|theirAction) to signify that either of them should be detected.

// TODO: Need to add levels of severity per pattern because some are not severe like the #define above.

// SHOULD DO:
//   - Consider nested messages betweeen arguments (beside pseudo-name?, fake name?)

// RULE(S) in generating expressions
//   There should be at least 1 group, because that will serve as the main group to match.
//   This is to support non-capturing groups and to ignore some parts but still needs to match it.
//   Other groups than group 1 will not be included in a match on CResult
//   In regex, if there are nested groups it seems that the outermost group is considered to be the first.

-(NSMutableArray *) generatePatterns
{
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

        
        for ( CKeywordInstance *objInstance in aInstances )
        {
            // Array of strings, by default it points to the [METHODS]
            NSMutableArray  *aPatterns = [ NSMutableArray arrayWithArray: [objInstance getMethods] ] ;
            
            // Hope the compiler strips this default call
            // Originally this part needs to get overriden on the subclasses
            if ( ![ self onPreProcessPatterns: aPatterns onInstance: objInstance ] )
            {
                break ;
            }
            
            // This should not be happening but just in case
            // The assumption is there should be at least one METHOD
            if ( ![aPatterns count] )
            {
                continue ;
            }
            
            NSMutableArray *aszValues = [ [[NSMutableArray alloc] init] autorelease ] ;
            
            if ( !aszValues )
            {
                break ; // this is serious!
            }
            
            NSArray *aArgs = [objInstance getArgs] ;
            
            for ( NSString *szArg in aArgs )
            {
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
                
                // Attach values to corresponding parameters
                if ( ![self applyToPatterns: aPatterns theParam: szParam withValue: szValue] )
                {
                    continue ;
                }
                
                [aszValues addObject: szValue] ;
            }
            
            // Should be done only once
            // Attach space recognition in between parameters
            if ( ![self addSpaceToPatterns: aPatterns] )
            {
                continue ; // There must be something wrong about it to fail
            }
            
            // Add extra patterns for each NS* values
            for ( NSString *szValue in aszValues )
            {
                // Skip non-NS values
                if ( ![self isNSvalue: szValue] )
                {
                    continue ;
                }
                
                // Work on every value but should be done on a separate loop
                // if it should contain colons(:), due to a call to addSpaceToPatterns()
                // Attach extra stuff to patterns
                if ( ![self addExtraToPatterns: aPatterns theValue: szValue] )
                {
                    continue ; // In case there is a need to add more things after extras
                }
            }
            
            [aAllPatterns addObjectsFromArray: aPatterns] ;
        }
    } while ( _PASSING_ ) ;
    
    return aAllPatterns ;
}

// Default implmentation does nothing
- (BOOL) onPreProcessPatterns: (NSMutableArray *)aszPatterns onInstance: (CInstance *)objInstance
{
    return TRUE ;
}

// Default implmentation does nothing
- (BOOL) onPreConvertPatternsToRegEx: (NSMutableArray *)aszPatterns
{
    return TRUE ;
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
        
        // String patterns, no need to retain or release this it will
        // be obliterated after this method goes out of scope
        NSMutableArray *aAllPatterns = [ self generatePatterns ] ;
        
        if ( ![aAllPatterns count] )
        {
            break ;
        }

        // Originally this part needs to get overriden on the subclasses

        if ( ![self onPreConvertPatternsToRegEx: aAllPatterns] )
        {
            break ;
        }
        
        aRet = [ NSArray arrayWithArray: [self toExpressions: aAllPatterns] ] ;
        
        if ( !aRet || ![aRet count] )
        {
            break ;
        }
        
        [self setRegExpressions: aRet] ;
        
    } while ( _PASSING_ ) ;
    
    return aRet ;
}

- (BOOL) isMultipleArg: (NSArray *) aszArgs
{
    return ( [aszArgs count] > 1 ) ;
}


// Syntax:
// ARG = [PARAM]:[VALUE]
- (BOOL) splitArg: (NSString *)szArg toParam: (NSString **)pszParam toValue: (NSString **)pszValue
{
    BOOL bRet = FALSE ;
    
    do
    {
        if ( (![szArg length]) || (!pszParam) || (!pszValue) )
        {
            break ;
        }
        
        NSArray *aszParts = [szArg componentsSeparatedByString: @":"] ;
        
        // Check for syntax as shown above
        if ( [aszParts count] > 2 )
        {
            // Only one colon (:) is allowed
            break ;
        }
        
        *pszParam = aszParts[0] ;
        *pszValue = aszParts[1] ;
        
        if ( (![*pszParam length]) || (![*pszValue length]) )
        {
            break ;
        }
        
        // Restore colon(:) as this is the mark of a parameter (name?)
        *pszParam = [ *pszParam stringByAppendingString: @":" ] ;
        
        bRet = TRUE ;
        
    } while ( _PASSING_ ) ;
    
    return bRet ;
}

- (BOOL) isLastParamInPattern: (NSString *) szPattern thisParam: (NSString *) szParam
{
    NSRange posParam = [ szPattern rangeOfString: szParam ] ;
    
    BOOL bRet = FALSE ;
    
    do
    {
        if ( NSEqualRanges( posParam, NSMakeRange(NSNotFound, 0) ) )
        {
            break ;
        }
        
        bRet = ( posParam.location >= [szPattern length] - [szParam length] ) ;
        
    } while ( _PASSING_ ) ;
    
    return bRet ;
}

// This RegEx will match the following cases: ((\s*\(\s*)*|\s*)YES((\s*\)\s*)*|\s*)

// Evolution:
// ((\s*\(\s*)*|\s*)YES((\s*\)\s*)*|\s*)
// ((\s*\(\s*)*|\s*)YES((\s*\)\s*)+|\s*)

// Finale:
// ((\s*\(\s*)+|\s*)YES((\s*\)\s*)+|\s*)

// Cases:
//:YES
//: YES
//: YES
//: YES

//:(YES)
//: (YES)
//: ( YES)
//: ( YES )
//:( YES)
//:( YES )
//:(YES )

//:((YES))
//: ((YES))
//: (( YES))
//: (( YES ))
//:(( YES)
//:(( YES ))
//:((YES ))

// down to any combination you want as long as the parenthesis matches but maybe not
// this kind of pattern but who codes like this? -> (()()YES)

//
// Helper methods, thus have lesser checks
// Basically returns TRUE if nothing is wrong and FALSE otherwise.
//

// DONE: Consider this pattern: (?:\b)(setAllowsAnyHTTPSCertificate\s*:((\s*\(\s*)+|\s*)(YES|TRUE|true)((\s*\)\s*)+|\s*))
//       to match this case: URLRequest setAllowsAnyHTTPSCertificate:(YES ) forHost:[URL host]];

// Sample Input: szParam=[setAllowsAnyHTTPSCertificate:] szArg=[setAllowsAnyHTTPSCertificate:(YES|TRUE|true)]
// Sample Output: [setAllowsAnyHTTPSCertificate\s*:((\s*\(\s*)+|\s*)(YES|TRUE|true)((\s*\)\s*)+|\s*)]

// This new version is with parenthesis recognition
// It doesn't matter anymore if is last parameter or not with the new regex pattern in the (\s*YES\s*) thing...

//TODO: Refine these polymorphs

- (NSMutableArray *) applyToPatterns: (NSMutableArray *)aszPatterns theParam: (NSString *)szParam withValue: (NSString *) szValue
{
    NSMutableArray *aszRet = aszPatterns ;
    
    do
    {
        // Insert space recognition before colon of the parameter (named parameter came in to mind)
        NSString *szWorkParam = [ szParam stringByReplacingOccurrencesOfString: @":" withString: @"\\s*:" ] ;
        
        // Adds parenthesis recognition here
        NSString *szWorkArg = [ [NSString alloc] initWithFormat: @"%@((\\s*\\(\\s*)+|\\s*)%@((\\s*\\)\\s*)+|\\s*)", szWorkParam, szValue ];
        
        for ( int iCtr = 0; iCtr < [aszPatterns count]; iCtr++ )
        {
            aszPatterns[iCtr] = [ aszPatterns[iCtr] stringByReplacingOccurrencesOfString:szParam withString: szWorkArg ] ;
        }
        
    } while ( _PASSING_ ) ;
    
    return aszRet ;
}

- (NSMutableArray *) applyToPatterns: (NSMutableArray *)aszPatterns theParam: (NSString *)szParam withValue: (NSString *) szValue
includeCaster: (BOOL) bIncludeCaster

{
    NSMutableArray *aszRet = aszPatterns ;
    
    do
    {
        if ( bIncludeCaster )
        {
            aszRet = [self applyToPatterns: aszPatterns theParam: szParam withValue: szValue] ;
            break ;
        }
        
        // Insert space recognition before colon of the parameter (named parameter came in to mind)
        NSString *szWorkParam = [ szParam stringByReplacingOccurrencesOfString: @":" withString: @"\\s*:" ] ;
        
        // Don't include parenthesis recognition here aka Caster
        NSString *szWorkArg = [ [NSString alloc] initWithFormat: @"%@\\s*%@\\s*", szWorkParam, szValue ] ;
        
        for ( int iCtr = 0; iCtr < [aszPatterns count]; iCtr++ )
        {
            aszPatterns[iCtr] = [ aszPatterns[iCtr] stringByReplacingOccurrencesOfString:szParam withString: szWorkArg ] ;
        }
        
        [szWorkArg release] ;
        
    } while ( _PASSING_ ) ;
    
    return aszRet ;
}



- (NSMutableArray *) applyToPatterns: (NSMutableArray *)aszPatterns theParam: (NSString *)szParam withValue: (NSString *) szValue returnOnlyReplaced: (BOOL) bReturnOnlyReplaced includeCaster: (BOOL) bIncludeCaster
{
    NSMutableArray *aszRet = aszPatterns ;
    
    do
    {
        if ( !bReturnOnlyReplaced )
        {
            aszRet = [self applyToPatterns: aszPatterns theParam: szParam withValue: szValue includeCaster: bIncludeCaster] ;
            break ;
        }
        
        aszRet = [ [[NSMutableArray alloc] init] autorelease ] ;
        
        if ( !aszRet )
        {
            break ;
        }
        
        // Insert space recognition before colon of the parameter (named parameter came in to mind)
        NSString *szWorkParam = [ szParam stringByReplacingOccurrencesOfString: @":" withString: @"\\s*:" ] ;
        
        // Adds parenthesis recognition here
        NSString *szWorkArg = nil ;
        
        if ( bIncludeCaster )
        {
            szWorkArg = [ [NSString alloc] initWithFormat: @"%@((\\s*\\(\\s*)+|\\s*)%@((\\s*\\)\\s*)+|\\s*)", szWorkParam, szValue ] ;
        }
        else
        {
            szWorkArg = [ [NSString alloc] initWithFormat: @"%@\\s*%@\\s*", szWorkParam, szValue ] ;
        }
        
        NSRange rangeNotFound = NSMakeRange( NSNotFound, 0 ) ;
        
        for ( NSString *szPattern in aszPatterns )
        {
            NSRange rangeParam = [szPattern rangeOfString: szParam] ;
            
            // [PARAM] found?
            if ( !NSEqualRanges( rangeParam, rangeNotFound ) )
            {
                // add the replaced item
                [ aszRet addObject: [szPattern stringByReplacingOccurrencesOfString:szParam withString: szWorkArg] ] ;
            }
        }
        
        [szWorkArg release] ;
        
    } while ( _PASSING_ ) ;
    
    return aszRet ;
}

- (BOOL) addExtraToPatterns: (NSMutableArray *)aszPatterns theValue: (NSString *)szValue
{
    BOOL bRet = FALSE ;
    
    do
    {
        // WARNING: Do not add extra with colon(:) because it will be broken by addSpaceToPatterns(),
        //          see generateExpressions() for details.
        // Assignment
        NSString *aszExtras[] =  { [ NSString stringWithFormat: @"(=(\\s*|\\s*\\(.*?\\)\\s*)%@)", szValue ],
            // Define
            [ NSString stringWithFormat: @"(#define\\s+.*?\\s*%@)", szValue ] } ;
        
        for ( int iCtr = 0; iCtr < _countof(aszExtras); iCtr++ )
        {
            [ aszPatterns addObject: aszExtras[iCtr] ] ;
        }
        
        bRet = TRUE ;
    } while ( _PASSING_ ) ;
    
    return bRet ;
}

//Detects NS values (or enums from NS)
- (BOOL) isNSvalue: (NSString *) szValue
{
    BOOL bRet = TRUE ;

    do
    {
        NSError *err = nil ;
        
        NSRegularExpression *regEx = [NSRegularExpression regularExpressionWithPattern: @"\\bNS" options:0 error: &err] ;
        
        if ( !regEx || err )
        {
            break ;
        }
        
        bRet = ( [regEx numberOfMatchesInString: szValue options:0 range: NSMakeRange( 0,  [szValue length])] > 0 ) ;
        
    } while ( _PASSING_ ) ;

    return bRet ;
}


//// This is the older version
//- (BOOL) applyToPatterns: (NSMutableArray *)aszPatterns theParam: (NSString *)szParam withArg: (NSString *) szArg
//{
//    BOOL bRet = FALSE ;
//
//    do
//    {
//        for ( int iCtr = 0; iCtr < [aszPatterns count]; iCtr++ )
//        {
//            NSString *szWorkArg = szArg ;
//
//            if ( ![self isLastParamInPattern: aszPatterns[iCtr]thisParam: szParam] )
//            {
//                // add space recognition, a space might not always be necessary so see the "if" statement above (thisParam)
//                szWorkArg = [[NSString alloc] initWithFormat: @"%@\\s*", szArg] ;
//            }
//
//            aszPatterns[iCtr] = [ aszPatterns[iCtr] stringByReplacingOccurrencesOfString:szParam withString: szWorkArg ] ;
//        }
//
//        bRet = TRUE ;
//    } while ( _PASSING_ ) ;
//
//    return bRet ;
//}


@end // CKeywordCallerVuln


