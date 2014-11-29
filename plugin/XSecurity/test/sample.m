
// sample 1

URLCredential *credential = [NSURLCredential credentialWithIdentity:identity certificates:(NSArray*)certArray persistence:NSURLCredentialPersistencePermanent];

NSURLProtectionSpace *protectionSpace = [[NSURLProtectionSpace alloc]
                                         initWithHost: @"myhostname"
                                         port: 443
                                         protocol: @"https"
                                         realm: nil
                                         authenticationMethod: NSURLAuthenticationMethodClientCertificate];

[[NSURLCredentialStorage sharedCredentialStorage]
 setDefaultCredential: credential
 forProtectionSpace: protectionSpace];


// sample 2

URLCredential *credential = [NSURLCredential credentialWithUser: someUser password: [someClass getPassword] persistence:NSURLCredentialPersistencePermanent];



// sample 3

[credential initWithIdentity: (SecIdentityRef)identity certificates: (NSArray *) someCertificates persistence:NSURLCredentialPersistencePermanent];


// sample 4
[credential initWithUser: (NSString *) someUser password: [someClass getPassword] persistence:NSURLCredentialPersistencePermanent];


// sample 5
NSURLCredentialPersistence myPersistence = NSURLCredentialPersistencePermanent ;

// sample 6
#define someDef NSURLCredentialPersistencePermanent

// sample 7
int iCtr = (int) (float *) NSURLCredentialPersistencePermanent ;

// sample 8 no detection, we know it already, let's say _whatever_ is #define for type casting
int iCtr = (int) (float *)  NSURLCredentialPersistencePermanent ;

// sample 9
URLRequest setAllowsAnyHTTPSCertificate:YES forHost:[URL host]];

// sample 10
[challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];

// sample 11
[[objChallenger getSender]continueWithoutCredentialForAuthenticationChallenge:challenge];

// sample 12
URLRequest setAllowsAnyHTTPSCertificate:(YES)forHost:[URL host]];

//// sample 13
//NSDictionary *properties = [NSDictionary dictionaryWithObjectsAndKeys: 
// [NSNumber numberWithBool:YES], kCFStreamSSLAllowsExpiredCertificates, 
// [NSNumber numberWithBool:YES], kCFStreamSSLAllowsAnyRoot, [NSNumber numberWithBool:NO], kCFStreamSSLValidatesCertificateChain, kCFNull,kCFStreamSSLPeerName, nil];


// sample 13-15
NSDictionary *properties = [NSDictionary dictionaryWithObjectsAndKeys: 
 [NSNumber numberWithBool:YES], kCFStreamSSLAllowsExpiredCertificates, 
 [NSNumber numberWithBool:YES], kCFStreamSSLAllowsAnyRoot, [NSNumber numberWithBool:NO], kCFStreamSSLValidatesCertificateChain, kCFNull,kCFStreamSSLPeerName, nil];


//
////
////// comment test #1
////
/////* oneline comment in multiline commenter */
////
/////* multiline comment in
//// multi-line commenter */
////
////// one line comment in oneline commenter
////
////someString = @"/*This is a comment inside a string */" ;
////someStringToo = @"//This is a comment inside a string" ;
////
////// /*
////some_code() ;
////// */
////
////NSString *test = @    "yello!" ;
//////initial regex: 
////((/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|(//.*))
////
////(:?[^"]*)((/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|(//.*))(:?[^"]*)
////
////
//////not inside literal string (but not working, why?)
////\+(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)
////(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)
////
////
////%%%%%%%%%%%% HERE %%%%%%%%%%%%  
////   -------------------------------------------------------------
////   // comment test #1
////   /* oneline comment in multiline commenter */
////                 
////   /* multiline comment in
////    multi-line commenter */
////   // one line comment in oneline commenter
////   somestringxxx = @ "/*This is a comment inside a string xxx*/" ;
////   someStringToo = @"//This is a comment inside a string" ;
////   // /*
////   some_code() ;
////   // */
////   -------------------------------------------------------------
////Does not detect the following, which is great!
////   somestringxxx = @ "/*This \" is a comment \"  \
////   inside a string xxx*/\
////   " ;
////
////
////
//
// sample 16

@implementation NSURLRequest

+ (BOOL)allowsAnyHTTPSCertificateForHost:(NSString *)host {
    
if ( this ) 
{
   return YES;
}

}
@end


// sample 17

@implementation NSURLRequest

+ (BOOL)allowsAnyHTTPSCertificateForHost:(NSString *)host {

BOOL bRet = TRUE ;
    
if ( this ) 
{
   return bRet;
}

@end
}
@end


// sample 18

NSLog( "password %@", pwd ) ;


// sample 19
NSMutableDictionary *query = [NSMutableDictionary dictionary];
 
 [query setObject:(id)kSecClassGenericPassword forKey:(id)kSecClass];
 [query setObject:account forKey:(id)kSecAttrAccount];
 [query setObject:(id)kSecAttrAccessibleAlways forKey:(id)kSecAttrAccessible];
 [query setObject:[inputString dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecValueData];

 OSStatus error = SecItemAdd((CFDictionaryRef)query, NULL);


// sample 20-21

@implementation SampleApp


- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation 
{
 
  // Perform transaction like Skype which allowed a malicious call
 
  return YES;
}


- (BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url
{
// Ask for authorization
// Perform transaction

  return YES ;
}


@end

// sample 22
NSUserDefaults *credentials = [NSUserDefaults standardUserDefaults];
[credentials setObject:self.username.text forKey:@"username"];
[credentials setObject:self.password.text forKey:@"password"];
[credentials synchronize];


// sample 23
NSString *name =[[NSUserDefaults standardUserDefaults] stringForKey: USERNAME] ;



// Adding new sample data see what will happen.
