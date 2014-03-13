//
//  CVulnCategory.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 3/3/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CVulnCategory.h"
#import "XSecDefs.h"

@implementation CVulnCategory

- (id)init
{
    do
    {
        self = [super init] ;

        if ( !self )
        {
            break ;
        }
        m_szName        = nil ;
        m_eSeverity     = E_SEVERITY_WARN ;
        m_szDescription = nil ;
        m_dicReferences = nil ;

    } while ( _PASSING_ ) ;
    
    return self ;
}

- (id)initWithName: (NSString *)szName  eSeverity: (E_SEVERITY)eSeverity szDescription: (NSString *)szDescription dicReferences: (NSDictionary *) dicReferences
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_szName        = szName,        [m_szName retain] ;
        m_eSeverity     = eSeverity ;
        m_szDescription = szDescription, [m_szDescription retain] ;
        m_dicReferences = dicReferences, [m_dicReferences retain] ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_szName        release], m_szName         = nil ;
                               m_eSeverity      = E_SEVERITY_INVALID ;
    [m_szDescription release], m_szName         = nil ;
    [m_dicReferences release], m_dicReferences  = nil ;
    
    [super dealloc] ;
}

- (NSString *) getName
{
    return m_szName ;
}

- (E_SEVERITY) getSeverity
{
    return m_eSeverity ;
}

- (NSString *) getDescription
{
    return m_szDescription ;
}

- (NSArray  *) getReferencesAt: (NSString *) szRefKind
{
    NSArray *aRet = nil ;
    
    do
    {
        // nil or empty
        if ( ![szRefKind length] )
        {
            break ;
        }
        
        if ( !m_dicReferences )
        {
            break ;
        }
        
        // szRefKind = "CWE" or "OWASP"
        aRet = [m_dicReferences objectForKey: szRefKind] ;
        
    } while ( _PASSING_ ) ;

    return aRet ;
}


@end
