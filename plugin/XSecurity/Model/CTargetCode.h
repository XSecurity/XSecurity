//
//  CTargetCode.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>

//////////////////////////////////////////////////////////////////////////////////////

@interface CTargetCode : NSObject < NSCopying >
{
    
@private
    NSMutableString *m_szData ;
}


// Temporary container, might change later as necessary. It seems 4.2 billon characters is enough
// TODO: As the need rises, add more getter here for other forms of data.
// Not really sure if readonly here can really write protect m_szData here.
//@property (copy, getter = getData, atomic) NSMutableString *m_szData ;

// NOTE:
// I decided to removed getData() because it should be an internal method

- (id) init ;
- (id) initWithData: (NSString *) szData ;
- (id) initWithFile: (NSString *) szFilePath ;
- (void) dealloc ;

- (BOOL) log ;

- (NSString *)getDataAsString ;
- (BOOL) maskCommentWith: (const unichar) chMask ;
@end