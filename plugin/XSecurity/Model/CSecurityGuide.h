//
//  CSecurityGuide.h
//  XSecurity
//
//  Created by Tokuji Akamine on 3/7/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CSecurityGuide : NSObject

@property (nonatomic, retain) NSString *m_szName;
@property (nonatomic, retain) NSArray  *m_aSignatures;
@property (nonatomic, retain) NSString *m_szCategory;
@property (nonatomic, retain) NSString *m_szDescription;

@end
