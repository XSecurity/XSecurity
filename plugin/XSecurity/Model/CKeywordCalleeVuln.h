//
//  CKeywordCalleeVuln.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/12/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "CKeywordVuln.h"

@interface CKeywordCalleeVuln : CKeywordVuln <PSubVulnActions>

// Default constructor
- (id) init ;

@end
