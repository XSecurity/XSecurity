//
//  CVulnController.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 12/19/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CVulnerability.h"
#import "CTargetCode.h"

#import "CSensitiveInfoKeywords.h"

#import "CInstance.h" //Temp for CSensitiveInfoKeywords

//TODO: Consider hierarchy here in the future, a dictionary maybe,
//      but for now it is a three dimentional array of array of array of (CResult *)

@interface CVulnController : NSObject
{
    
@private
    NSMutableArray  *m_aVulns ;
}

+ (CSensitiveInfoKeywords *) createSensitiveInfoKeywordsObject ;
+ (NSDictionary *) getVulnCategories ;

- (id) init ;
- (void) dealloc ;

- (NSArray *)      detect: (CTargetCode *) objTarget bCommentRemoved: (BOOL) bCommentRemoved ;
- (void)           logResults: (NSArray *)aaResults ;

@end
