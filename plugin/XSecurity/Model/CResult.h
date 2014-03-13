//
//  CResult.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CTargetCode.h"
#import "CVulnerability.h"

//////////////////////////////////////////////////////////////////////////////////////

@interface CResult : NSObject
{
    
@private
    NSRange         m_aggRange ;
    CTargetCode     *m_objTarget ;      // Seems necessary to add a reference
    CVulnerability  *m_objVuln ;        // This too seems necessary
    NSString        *m_szExpression ;   // The regex string/pattern that matched
}

- (id) init ;
- (id) initWithData: (NSRange) aggRange objTarget: (CTargetCode *)objTarget objVuln: (CVulnerability *) objVuln szExpression: (NSString *)szExpression ;

- (void) log: (int) iID ;

// Hard getters
- (NSRange)          getRange ;
- (CTargetCode *)    getTarget ;
- (CVulnerability *) getVulnerability ;
- (NSString *)       getExpression ;

@end
