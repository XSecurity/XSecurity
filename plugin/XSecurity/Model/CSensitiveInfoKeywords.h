//
//  CSensitiveInfoKeywordsEx.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/31/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>

//////////////////////////////////////////////////////////////////////////////////////

@interface CSensitiveInfoKeywords : NSObject
{
    
@private
    // Array of regular expression patterns
    NSMutableArray *m_aRegKeywords ;
}

- (id) init ;
- (id) initWithKeywords: (NSArray *) aszKeywords ;
- (void) dealloc ;

//TODO: Consider if this is really necessary
//- (NSArray *) getKeywords ;

- (BOOL) isKeywordSensitive: (NSString *) szKeyword ;
- (NSString *) getCombinedPatterns ;
@end
