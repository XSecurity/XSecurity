//
//  CLogicVuln.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CLogicVuln.h"

@implementation CLogicVuln

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
    return nil ;
}

- (NSArray *) generateExpressions
{
    return nil ;
}
@end
