//
//  CKeywordCallerVuln.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/2/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CKeywordVuln.h"

// Description:
//    Keyword matching for ARGs, In SecurityPolicy.plist, typically matches calls/callers of [Methods]
//    matches each [Args] with each [Methods], to form a pattern to detect
// where
//  [Methods] = <parameter:> <parameter:> <parameter:>
//  [Args]    = <parameter:> <value>
@interface CKeywordCallerVuln : CKeywordVuln <PSubVulnActions>
{
    
}

// Default constructor
- (id) init ;

@end
