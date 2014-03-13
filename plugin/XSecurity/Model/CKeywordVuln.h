//
//  CKeywordVuln.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CVulnerability.h"
//////////////////////////////////////////////////////////////////////////////////////

@interface CKeywordVuln : CVulnerability <PSubVulnActions>
{
    
}

// m_aobjInstances here is an Array of CKeywordInstances
+ (NSString *) ensure1stGroupOnPattern: (NSString *)szPattern ;
+ (NSString *) ensure1stGroupOnPattern: (NSString *)szPattern szPrefix: (NSString *)szPrefix ;

@end
