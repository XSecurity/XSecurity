//
//  CPureKeywordVuln.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CPureKeywordVuln.h"
#import "CInstance.h"

// Inherit protected methods from CKeywordVuln
@interface CPureKeywordVuln (Protected)
- (void)      setRegExpressions: (NSArray *) aRegExps ;
- (BOOL)      addSpaceToPatterns: (NSMutableArray *)aszPatterns ;
- (BOOL)      ensure1stGroupInPatterns: (NSMutableArray *)aszPatterns ;
- (NSArray *) toExpressions:(NSMutableArray *) aszPatterns ;
@end

@implementation CPureKeywordVuln

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
            
            NSMutableArray *aszKeywords = [[NSMutableArray alloc] init] ;
            
            // Out of memory, no point of continuing
            if ( !aszKeywords )
            {
                break ;
            }
            
            // Collect Methods, Args and Keywords as Keywords
            NSString *aszNames[] = { @"Methods", @"Args", @"Keywords" } ;
            
            for (int iCtr = 0; iCtr < _countof(aszNames); iCtr++)
            {
                NSMutableArray *aTreatAsKeywords = [ dicClassName objectForKey: aszNames[iCtr] ] ;
                                      
                if ( !aTreatAsKeywords )
                {
                    continue ;
                }

                // Except Keywords which is assumed to be self-contained,
                // add space recognition to them
                if ( [aszNames[ iCtr ] isEqualToString: @"Keywords"] )
                {
                    [self ensure1stGroupInPatterns: aTreatAsKeywords] ;
                }
                else
                {
                    [self addSpaceToPatterns: aTreatAsKeywords] ;
                }
                
                [aszKeywords addObjectsFromArray: aTreatAsKeywords] ;
            }
            
            CPureKeywordInstance *objInstance = [ [CPureKeywordInstance alloc] initWithClass: szKey withKeywords: [NSArray arrayWithArray: aszKeywords] ] ;
            
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

- (NSArray *) generateExpressions
{
    NSArray *aRet = [self getRegExpressions] ;

    do
    {
        // Generated previously?
        if ( aRet )
        {
            break ;
        }
        
        NSMutableArray *aWorkArray = [ [NSMutableArray alloc] init ] ;
        NSArray *aInstances = [self getInstances] ;
        
        if ( !aWorkArray || !aInstances )
        {
            break ;
        }
        
        for ( CPureKeywordInstance *objInstace in aInstances )
        {
            [aWorkArray addObjectsFromArray: [objInstace getKeywords]] ;
        }
        
        aRet = [self toExpressions: aWorkArray] ;
        
        if ( !aRet )
        {
            break ;
        }
        
        [self setRegExpressions: aRet] ;
        
    } while ( _PASSING_ ) ;

    return aRet ;
}

@end
