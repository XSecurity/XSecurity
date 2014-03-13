//
//  NSAttributedString+Hyperlink.h
//  XSecurity
//
//  Created by Tokuji Akamine on 8/28/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSAttributedString (Hyperlink)
+(id)hyperlinkFromString:(NSString*)inString withURL:(NSURL*)aURL;
@end
