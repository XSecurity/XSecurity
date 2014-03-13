//
//  CResult.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CResult.h"
#import "CLog.h"

//////////////////////////////////////////////////////////////////////////////////////

@implementation CResult

- (id) init
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_aggRange     = NSMakeRange( 0, 0 ) ;
        m_objTarget    = nil ;
        m_objVuln      = nil ;
        m_szExpression = nil ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (id) initWithData: (NSRange) aggRange objTarget : (CTargetCode *) objTarget objVuln: (CVulnerability *) objVuln szExpression: (NSString *)szExpression
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }
        
        m_aggRange     = aggRange ;
        m_objTarget    = objTarget,    [m_objTarget retain] ;
        m_objVuln      = objVuln  ,    [m_objVuln retain] ;
        m_szExpression = szExpression, [m_szExpression retain] ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    m_aggRange      = NSMakeRange( NSNotFound, 0 ) ;
    [m_objTarget    release], m_objTarget    = nil ;
    [m_objVuln      release], m_objVuln      = nil ;
    [m_szExpression release], m_szExpression = nil ;
    
    [super dealloc] ;
}

- (void) log: (int) iID
{
    do
    {
        NSString *szMatch = [ [m_objTarget getDataAsString] substringWithRange: m_aggRange ] ;
        
        [CLog xlogv: @"------- ID: %d", iID] ;
        [CLog xlogv: @"Category: %@", [[m_objVuln getCategory] getName]] ;
        [CLog xlog:  @"Vuln  " withObject: m_objVuln] ;
        [CLog xlog:  @"Expr  " withObject: m_szExpression] ;
        [CLog xlog:  @"Match " withObject: szMatch] ;
        [CLog xlogv: @"Range : %d, %d", m_aggRange.location, m_aggRange.length] ;
        
    } while ( _PASSING_ ) ;
}

// Hard getters!
- (NSRange) getRange
{
    return m_aggRange ;
}

- (CTargetCode *) getTarget
{
    return  m_objTarget ;
}

- (CVulnerability *) getVulnerability
{
    return m_objVuln ;
}

- (NSString *) getExpression
{
    return m_szExpression ;
}


@end // CResult
