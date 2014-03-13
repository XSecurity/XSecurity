//
//  CPureKeywordVuln.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CKeywordVuln.h"

@interface CPureKeywordVuln : CKeywordVuln <PSubVulnActions>
{
    
}
// m_aobjInstances here is an Array of CPureKeywordInstances

// Default constructor
- (id) init ;

@end
