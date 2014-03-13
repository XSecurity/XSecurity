//
//  SecurityGuideWindowController.m
//  XSecurity
//
//  Created by Tokuji Akamine on 8/23/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CSecurityGuideWindowController.h"
#import <objc/objc.h>

@implementation CSecurityGuideWindowController

-(id)init {
	self = [super initWithWindowNibName:@"SecurityGuideWindowController"];
	if (self) {
	}
	return self;
}

-(void)dealloc {
	[currentViewContents release];
	[super dealloc];
}

@end
