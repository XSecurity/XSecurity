//
//  CViewController.m
//  CLangTest
//
//  Created by Pedraita, Raymund on 2/6/14.
//  (C) 2014 XSecurity Project. All rights reserved.
//

#import "CViewController.h"
#import <sqlite3.h>

@interface CViewController ()

@end

@interface NSURLRequest(PrivateAPI)
+ (void)setAllowsAnyHTTPSCertificate:(BOOL)allow forHost:(NSString*)host;
@end

@implementation CViewController

#pragma mark NSURLConnection Delegate Methods

- (id)initWithNibName:(NSString *)nibName bundle: (NSBundle *)nibBundle articleTitles: (NSMutableArray *)articles
{
    self = [super init] ;
    
    return self ;
}

- (void) pushViewController: (UIViewController *)viewController animated: (BOOL)bAnimated
{
    NSString *szAccount = @"Taro" ;
    NSString *szPassword = @"RakuRaku" ;
    
    // 1.) SHOULD DETECT: Leaking sensitive information via logs
    NSLog( @"Account and  password %@ : %@", szAccount, szPassword) ;
}

- (IBAction) sample_SQLInjection: (id)sender
{
    NSString *szSearchFieldText = @"sample search text that will receive user supplied data" ;
    
    // Search the database for articles matching the search string.
    NSString *dbPath = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"articles.sqlite"];
    
    sqlite3 *db;
	const char *path = [dbPath UTF8String];
	
	if (sqlite3_open(path, &db) != SQLITE_OK)
    {
        return;
    }

    NSString *searchString = [szSearchFieldText length] > 0 ? [NSString stringWithFormat:@"%@%@%@", @"%", szSearchFieldText, @"%"] : @"%";

    NSString *query = [NSString stringWithFormat:@"SELECT title FROM article WHERE title LIKE '%@' AND premium=0", searchString];
    
//    NSString *query = @"SELECT title FROM article WHERE title LIKE ? AND premium=0";
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, nil);

//    sqlite3_bind_text(stmt, 1, [searchString UTF8String], -1, SQLITE_TRANSIENT);
    
    NSMutableArray *articleTitles = [[NSMutableArray alloc] init];
    
    // 2.) SHOULD DETECT:  SQL Injection
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        NSString *title = [[NSString alloc] initWithUTF8String:(char *)sqlite3_column_text(stmt, 0)];
        [articleTitles addObject:title];
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    // Create the articles (table) controller.
    CViewController *articlesController = [[CViewController alloc] initWithNibName:@"SQLInjectionArticlesViewController" bundle: nil articleTitles: articleTitles];
    
    // Pass the selected object to the new view controller.
    [self.navigationController pushViewController:articlesController animated:YES];
    
}

//- (IBAction) sample_failing_SQLInjection: (id)sender szString: (NSString *) szString
//{
//    // Search the database for articles matching the search string.
//    NSString *dbPath = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"articles.sqlite"];
//    
//    NSString *szSearchFieldText = @"sample search" ;
//    
//    NSString *szRedsearchString = [szSearchFieldText length] > 0 ? [NSString stringWithFormat:@"%@%@%@", @"%", szSearchFieldText, @"%"] : @"%";
//
//
//    sqlite3 *db;
//    const char *path = [dbPath UTF8String];
//
//    if (sqlite3_open(path, &db) != SQLITE_OK)
//    {
//        return;
//    }
//
// //   NSString *justAString = @"harmless" ;
////    NSString *searchString = @"harmless" ;
//    NSInteger iVal = 0 ;
//
////    NSString *query = [NSString stringWithFormat:@"SELECT title FROM article WHERE title LIKE '%@' AND premium=0", searchString];
//    NSString *query = [NSString stringWithFormat:@"SELECT title FROM article WHERE title LIKE '%@' AND premium=%ld", szRedsearchString, (long)iVal];
//
//    sqlite3_stmt *stmt;
//    sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, nil);
//
//    NSMutableArray *articleTitles = [[NSMutableArray alloc] init];
//
//    while (sqlite3_step(stmt) == SQLITE_ROW)
//    {
//        NSString *title = [[NSString alloc] initWithUTF8String:(char *)sqlite3_column_text(stmt, 0)];
//        [articleTitles addObject:title];
//    }
//
//    sqlite3_finalize(stmt);
//    sqlite3_close(db);
//}

//******************************************************************************
// SOLUTION
//
// To exploit the problem, try entering the following string in the search
// field...
//
// ' OR 1=1 --
//
// All free AND premium articles should show up in the search results.
//
// Rather than using stringWithFormat() to create the query string, use the
// built-in sqlite3_bind_text() method, which automatically sanitizes query
// parameters.
//
// In the sample_SQLInjection() method above, replace the query definition with...
//
// NSString *query = @"SELECT title FROM article WHERE title LIKE ? AND premium=0";
//
// Then, immediately after calling sqlite3_prepare_v2()...
//
// sqlite3_bind_text(stmt, 1, [searchString UTF8String], -1, SQLITE_TRANSIENT);
//
// This binds the search string to the query in a safe manner.
//******************************************************************************









//
//////////// test methods for Ignores Validation Error vuln ////////////
//

//////// extra methods //////
//- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
//{
////A response has been received, this is where we initialize the instance var you create
////so that we can append data to it in the didReceiveData method
////Furthermore, this method is called each time there is a redirect so reinitializing it
////also serves to clear it
//    
////    _responseData = [[NSMutableData alloc] init];
//}
//
//- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
//    // Append the new data to the instance variable you declared
////   [_responseData appendData:data];
//}
//
//- (NSCachedURLResponse *)connection:(NSURLConnection *)connection
//                  willCacheResponse:(NSCachedURLResponse*)cachedResponse {
//    // Return nil to indicate not necessary to store a cached response for this connection
//    return nil;
//}
//
//- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
//    // The request is complete and data has been received
//    // You can parse the stuff in your instance variable now
//    
//}
//
//- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
//    // The request has failed for some reason!
//    // Check the error var
//}

- (void)create_and_fire_a_connection
{
    // Create the request.
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"http://google.com"]];
    
    // Create url connection and fire request
    NSURLConnection *conn = [[NSURLConnection alloc] initWithRequest:request delegate:self];
}

//
////// methods with security concerns //////
//

//- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)not_me
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
//       id <NSURLAuthenticationChallengeSender> pSender = challenge.sender ;
//       [pSender continueWithoutCredentialForAuthenticationChallenge: challenge] ;

    // 3.) SHOULD DETECT:  Ignore Certificate Validation Errors
    //FIXME: This should be detected but not this time
    [challenge.sender continueWithoutCredentialForAuthenticationChallenge: challenge] ;
    
//
////    NSURLAuthenticationChallenge *test = nil ;
////    CMySender *mySender = nil ;
////
////    int acct = 0 ;
////    
////    if ( acct > 1 ) {
////        return ;
////    }
////    
//    NSURLAuthenticationChallenge *dont_display = [[NSURLAuthenticationChallenge alloc] init] ;
//    
//    [not_me.sender continueWithoutCredentialForAuthenticationChallenge: not_me] ;

}

-(void)xlogv:(NSString *)szFormat, ...
{
    va_list arg_list ;
    
    NSString *szActualSecretLog = [NSString stringWithFormat: @"[XSecurity] %@", szFormat] ;
    
    va_start( arg_list, szFormat ) ;

    //FIXME: This should be clarified if necessarily be detected.
    NSLogv( szActualSecretLog, arg_list ) ;
    
    va_end( arg_list ) ;
}

-(void) sample_LeakingLogs
{
//    NSString *szCopy = @"auth%@" ;
    NSString *szCopy = @"auth%@" ;
    NSString *szToken = @"ddd-" ;

//    NSString *szFormat = @"Authentication  Token: %@" ;
//    NSString *szFormat = szToken ;
    NSString *szFormat = szCopy ;
//    NSString *szFormat = nil ;
    
//    NSLog( szFormat, szToken);

    // 4.) SHOULD DETECT:  Leaking via log
    //FIXME: Not working
    [self xlogv: szFormat, szToken] ;
}

- (id)sample_LeakingPasteboard
{
    UIPasteboard *objPasteBoard = [UIPasteboard generalPasteboard] ;
  
    NSArray *emptyArray = nil ;

    NSArray *targetArray = [NSArray arrayWithArray: emptyArray] ;
// targetArray variant
// NSArray *targetArray = emptyArray ;
  
    NSString *szValue = @"take this literally!"  ;
//    NSString *szValue = @""  ;
  
    NSData *pTrickData = nil ;

    szValue = (NSString *)pTrickData ;
  
    NSData *pSampleData = nil ;
//    NSData *pSampleData = pTrickData ;
//    NSData *pSampleData = [ [NSData alloc] initWithBase64EncodedString: @"=yo! this is me!" options: 100 ] ;
  
    BOOL bChase = TRUE ;
    id myID = nil ;
    
    
    if ( bChase )
    {
//        [objPasteBoard setData: pSampleData forPasteboardType: @"myPasteBoard"] ;
//        [objPasteBoard setValue: szValue forPasteboardType: @"myPasteBoard"] ;
//        [objPasteBoard addItems: targetArray] ;
        
        // 5.) SHOULD DETECT:  Possibility of leaking pastebin information
        NSArray *items   = [objPasteBoard items  ] ;
//        NSString *string = [objPasteBoard string ] ;
//        NSArray *strings = [objPasteBoard strings] ;
//        UIImage *image   = [objPasteBoard image  ] ;
//        NSArray *images  = [objPasteBoard images ] ;
//        NSURL *URL       = [objPasteBoard URL    ] ;
//        NSArray *URLs    = [objPasteBoard URLs   ] ;
//        UIColor  *color  = [objPasteBoard color  ] ;
//        NSArray *colors  = [objPasteBoard colors ] ;
        
        
        myID = items   ;
//        myID = string  ;
//        myID = strings ;
//        myID = image   ;
//        myID = images  ;
//        myID = URL     ;
//        myID = URLs    ;
//        myID = color   ;
//        myID = colors  ;
    }

    return myID ;
}


- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    
    //    [self sample_InsecureDataStorageKeyChainKeywordPure] ;
    
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

//- (void)connection:(NSURLConnection *)connection didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
//{
//
//}
//
//- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
//{
//    
//}






////// methods with security concerns //////


//////////// test methods for Ignores Validation Error vuln ////////////

- (void) sample_IgnoreValidationError
{
    bool bYes = YES ;
//    NSURL *URL = [[NSURL alloc] init] ;
//    NSURL *URL = [NSURL URLWithString:@ "http://www.yahoo.com (url)"]  ;
    NSString *szURL = [NSString stringWithString: @"http://www.yahoo.com (string)"] ;

//    NSString *szEmpty = [NSString stringWithString: @""] ;

//    [NSURLRequest setAllowsAnyHTTPSCertificate: YES forHost: @"http://www.yahoo.com (url)" ] ;
    
    // 6.) SHOULD DETECT:  Possibility of leaking pastebin information
    [NSURLRequest setAllowsAnyHTTPSCertificate:bYes forHost: szURL ] ;

//szURL:0 {NSString *szURL = [NSString stringWithString: @"http://www.yahoo.com (string)"] ;}
//[URL host]:0 {NSURL *URL = [NSURL URLWithString:@ "http://www.yahoo.com (url)"]  ;}
//
    if ( bYes )
    {

    //    NSString *szNil = nil ;
    //    //    NSURL *URL = [[NSURL alloc] init] ;
    //    //    NSURL *URL = [NSURL URLWithString:@ "http://www.yahoo.com (url)"]  ;
    //    NSString *szURL = [NSString stringWithString: @"http://www.yahoo.com (string)"] ;
    //    //
    //    NSString *szEmpty = [NSString stringWithString: @""] ;
    //    NSString *szEmptyToo = [NSString stringWithString: @""] ;
    //
    //    if ( bYes )
    //    {
    //        //        [NSURLRequest setAllowsAnyHTTPSCertificate: bYes forHost: @"http://www.yahoo.com (url)" ] ;
    //        [NSURLRequest setAllowsAnyHTTPSCertificate: bYes forHost: szURL ] ;
    //    }
    
    }
}




- (void) sample_IgnoresValidationError

{
    NSLog( @"don't detect me!" ) ;
    
    bool bYes = YES ;

    if ( bYes )
    {

        // properties variations
        
        // NSDictionary
//        NSDictionary *properties = [NSDictionary dictionaryWithObjectsAndKeys:
//                                    [NSNumber numberWithBool:YES], kCFStreamSSLAllowsExpiredCertificates,
//                                    [NSNumber numberWithBool:YES], kCFStreamSSLAllowsAnyRoot, [NSNumber numberWithBool:NO],
//                                      kCFStreamSSLValidatesCertificateChain, kCFNull,kCFStreamSSLPeerName, nil] ;

        // NSMutableDictionary
//        NSMutableDictionary *properties = [NSMutableDictionary dictionaryWithObjectsAndKeys:
//                                    [NSNumber numberWithBool:YES], kCFStreamSSLAllowsExpiredCertificates,
//                                    [NSNumber numberWithBool:YES], kCFStreamSSLAllowsAnyRoot, [NSNumber numberWithBool:NO],
//                                      kCFStreamSSLValidatesCertificateChain, kCFNull,kCFStreamSSLPeerName, nil] ;

        // NSMutableDictionary with less parameters
        NSMutableDictionary *properties = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                           [NSNumber numberWithBool:YES], kCFStreamSSLAllowsExpiredCertificates,
                                           kCFNull,kCFStreamSSLPeerName, nil] ;
        
//        BOOL bTest = YES ;
        
//        [properties setObject: [NSNumber numberWithBool:NO] forKey: (id)kCFStreamSSLAllowsExpiredCertificates] ;
        
        UInt8 pData[] = "this is data" ;
        
        CFReadStreamRef inCfStream = CFReadStreamCreateWithBytesNoCopy( kCFAllocatorDefault, pData, _countof(pData), kCFAllocatorNull )  ;
        
        // 7.) SHOULD DETECT:  Should detect because of kCFStreamSSLAllowsExpiredCertificates variants set to properties
        if ( CFReadStreamSetProperty(inCfStream, kCFStreamPropertySSLSettings, (CFTypeRef)properties) == FALSE)
        {
            //FIXME: False positive NSLog detection, string problem
            NSLog(@"Failed to set SSL properties on read stream.");
        }
    }
    

    
    
}


//////////// test methods for Ignores Validation Error vuln ////////////


//FIXME: There is something wrong with the queries
//- (void) sample_InsecureDataStorageKeyChainKeywordPure
//{
//    NSMutableDictionary *query = [NSMutableDictionary dictionary];
//    NSMutableDictionary *old_query = [NSMutableDictionary dictionary];
//    
//    id testID = (id)CFBridgingRelease(kSecAttrAccessibleAlwaysThisDeviceOnly) ;
////    id testID = (id)CFBridgingRelease(0) ;
// 
//    BOOL bRet = true ;
//
//    if ( bRet )
//    {
//        [query setObject: testID forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;
//    }
//
//    // 8.) SHOULD DETECT:  Insecure data storage
//    OSStatus error = SecItemAdd((CFDictionaryRef)CFBridgingRetain(query), NULL);
//    
//    // 8.) SHOULD DETECT:  Insecure data storage
//    //OSStatus
//    error = SecItemUpdate((CFDictionaryRef)CFBridgingRetain(old_query), (CFDictionaryRef)CFBridgingRetain(query));
//
//    if ( error == errSecSuccess )
//    {
//        NSLog( @"Successful call to SecItemAdd()" ) ;
//    }
//    
//}

//
//
//-(void) setHere: (NSMutableDictionary *)q
//{
//    [q setObject: (id)CFBridgingRelease(kSecAttrAccessibleAlwaysThisDeviceOnly) forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;
//    
//}


//TODO: Figure out the variance of this code
- (void) sample_InsecureDataStorageKeyChainKeywordPure
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    NSString *szAccount = @"AccountName" ;
    NSString *szInputString = @"My Crazy Input String" ;
    
    
    [query setObject: (id)CFBridgingRelease(kSecClassGenericPassword) forKey: (id)CFBridgingRelease(kSecClass) ] ;
    
    [query setObject: szAccount forKey:(id) CFBridgingRelease(kSecAttrAccount) ] ;

  // Initial instance of this vulnerability
    [query setObject: (id)CFBridgingRelease(kSecAttrAccessibleAlways) forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;

    [query setObject: (__bridge id)kSecAttrAccessibleAlways forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;
    //
    // Just replicating some other instance/variants, this may not be a valid source code
    // what we just need here is a code that compiles
    //

    BOOL bRet = true ;
  
    if ( bRet )
    {
        [query setObject: (id)CFBridgingRelease(kSecAttrAccessibleAlwaysThisDeviceOnly) forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;
    }

    [query setObject: (id)CFBridgingRelease(kSecAttrAccessibleAfterFirstUnlock) forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;

//    [self setHere: query] ;
  
    OSStatus error = SecItemAdd((CFDictionaryRef)CFBridgingRetain(query), NULL);

    if ( error == errSecSuccess )
    {
        NSLog( @"Successful call to SecItemAdd()" ) ;
    }
    
    NSString *szNewAccount = @"New Account" ;
    NSMutableDictionary *updateQuery = [NSMutableDictionary dictionary] ;

    [query setObject: (id)CFBridgingRelease(kSecClassGenericPassword) forKey: (id)CFBridgingRelease(kSecClass) ] ;

    [query setObject: szNewAccount forKey:(id) CFBridgingRelease(kSecAttrAccount) ] ;


    // Give some other vulnerable
    [query setObject: (id)CFBridgingRelease(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;
    
    [query setObject:[ szInputString dataUsingEncoding:NSUTF8StringEncoding] forKey: (id) CFBridgingRelease(kSecValueData) ] ;
    
    
    error = SecItemUpdate( (CFDictionaryRef)CFBridgingRetain(query), CFBridgingRetain(updateQuery)) ;
    
    if ( error == errSecSuccess )
    {
        NSLog( @"Successful call to SecItemUpdate()" ) ;
    }
    
}




@end
