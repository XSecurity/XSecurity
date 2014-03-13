//
//  CInstance.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CInstance.h"

//////////////////////////////////////////////////////////////////////////////////////

@implementation CInstance
// Retain the original names not _m_... something
@synthesize m_szClass ;

- (id)initWithClass: (NSString *)szClass
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_szClass = szClass, [m_szClass retain] ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_szClass release], m_szClass = nil ;
    
    [super dealloc] ;
}

@end // CInstances


//////////////////////////////////////////////////////////////////////////////////////

@implementation CKeywordInstance
// Retain the original names not _m_... something
@synthesize m_aszMethods ;
@synthesize m_aszArgs ;


- (id) initWithClass: (NSString *) szClass withMethods: (NSArray *) aszMethods withArgs: (NSArray *) aszArgs
{
    do
    {
        self = [super initWithClass: szClass] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_aszMethods = aszMethods, [m_aszMethods retain] ;
        m_aszArgs    = aszArgs   , [m_aszMethods retain] ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_aszMethods release], m_aszMethods = nil ;
    [m_aszArgs    release], m_aszArgs = nil ;
    
    [super dealloc] ;
}

@end

//////////////////////////////////////////////////////////////////////////////////////

@implementation CPureKeywordInstance
// Retain the original names not _m_... something
@synthesize m_aszKeywords ;

- (id)initWithClass: (NSString *)szClass withKeywords: (NSArray *)aszKeywords
{
    do
    {
        self = [super initWithClass: szClass] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_aszKeywords = aszKeywords, [m_aszKeywords retain] ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_aszKeywords release], m_aszKeywords = nil ;
    
    [super dealloc] ;
}

@end // CPureKeywordInstances

//////////////////////////////////////////////////////////////////////////////////////

@implementation CKeywordCalleeInstance
@synthesize m_dicMethods ;

// I can't think where this can be used since you can directly access the dictionary
// in the first place. Take note it is not methods but but method so it is from
// Methods -> [Method Name]

- (NSArray *)getKeywordsFromDictionary: (NSDictionary *) dicMethod
{
    NSArray *aRet = nil ;
    
    do
    {
        if ( !dicMethod )
        {
            break ;
        }
        
        aRet = [dicMethod objectForKey: @"Keywords"] ;
        
    } while ( _PASSING_ ) ;

    // Can't autorelease aRet here because this method does not own
    // it in the first place
    return aRet ;
}

- (id)initWithClass:(NSString *)szClass withDicMethods: (NSDictionary *)dicMethods
{
    do
    {
        self = [super initWithClass: szClass] ;

        if ( !self )
        {
            break ;
        }
        
        m_dicMethods = dicMethods, [m_dicMethods retain] ;
    } while ( _PASSING_ ) ;

    return self ;
}

- (void) dealloc
{
    [m_dicMethods release], m_dicMethods = nil ;
    
    [super dealloc] ;
}

@end


//////////////////////////////////////////////////////////////////////////////////////

@implementation CKeywordSensitiveInstance
@synthesize m_aszFunctions ;

- (id)initWithClass:(NSString *)szClass withMethods: (NSArray *) aszMethods withArgs: (NSArray *) aszArgs withFunctions: (NSArray *)aszFunctions
{
    do
    {
        self = [super initWithClass: szClass withMethods: aszMethods withArgs: aszArgs] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_aszFunctions = aszFunctions, [m_aszFunctions retain] ;
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_aszFunctions release], m_aszFunctions = nil ;
    
    [super dealloc] ;
}
@end




