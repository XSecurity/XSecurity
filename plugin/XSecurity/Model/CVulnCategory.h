//
//  CVulnCategory.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 3/3/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CVulnerability.h"
#import <Foundation/Foundation.h>

@interface CVulnCategory : NSObject
{
@private
    NSString    *m_szName ;
    E_SEVERITY   m_eSeverity ;
    NSString    *m_szDescription ;
    NSDictionary *m_dicReferences ;
}

- (id)init ;
- (id)initWithName: (NSString *)szName eSeverity: (E_SEVERITY)eSeverity szDescription: (NSString *)szDescription dicReferences: (NSDictionary *) dicReferences ;

- (void) dealloc ;

- (NSString *) getName ;
- (E_SEVERITY) getSeverity ;
- (NSString *) getDescription ;
- (NSArray  *) getReferencesAt: (NSString *) szRefKind ;

@end
