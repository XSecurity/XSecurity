//
//  CViewController.h
//  CLangTest
//
//  Created by Pedraita, Raymund on 2/6/14.
//  (C) 2014 XSecurity Project. All rights reserved.
//

#import <UIKit/UIKit.h>

#define _countof( _obj_ ) ( sizeof(_obj_) / (sizeof( typeof( _obj_[0] ))) )

@interface CViewController : UIViewController

//@interface CViewController : UIViewController< NSURLConnectionDelegate >
{
    NSMutableData *_responseData ;
}

//- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)not_me ;
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge ;

@end


@interface CMySender: NSObject

- (id<NSURLAuthenticationChallengeSender>)sender;

@end