//////////////////
@interface NSURLRequest
+ (void)setAllowsAnyHTTPSCertificate:(BOOL)allow forHost:(NSString*)host; 
@end
  
[NSURLRequest setAllowsAnyHTTPSCertificate:YES forHost:[URL host]];

//////////////////
-(void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge (NSURLAuthenticationChallenge *)challenge;
  
[challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];



//////////////////
@interface NSURLRequest
+ (BOOL)allowsAnyHTTPSCertificateForHost:(NSString *)host;
@end
  
@implementation NSURLRequest
+ (BOOL)allowsAnyHTTPSCertificateForHost:(NSString *)host {
    return YES;
}
@end



//////////////////
NSDictionary *properties = [NSDictionary dictionaryWithObjectsAndKeys: 
 [NSNumber numberWithBool:YES], kCFStreamSSLAllowsExpiredCertificates, 
 [NSNumber numberWithBool:YES], kCFStreamSSLAllowsAnyRoot, [NSNumber numberWithBool:NO], kCFStreamSSLValidatesCertificateChain, kCFNull,kCFStreamSSLPeerName, nil];
 
 
if (CFReadStreamSetProperty(inCfStream, kCFStreamPropertySSLSettings, (CFTypeRef)properties) == FALSE) { NSLog(@"Failed to set SSL properties on read stream."); };



