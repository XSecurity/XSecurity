//
//  QuickHelpController.m
//  XSecurity
//
//  Created by Tokuji Akamine on 12/10/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"

#import "CQuickHelpController.h"
#import "CLog.h"
#import "CSecurityGuide.h"
#import "CVulnController.h"
#import "CVulnCategory.h"

@implementation CQuickHelpController
+ (id)sharedCenter {
	static CQuickHelpController* sharedInstance = nil;
	if(!sharedInstance) {
		sharedInstance = [[self alloc] init];
	}
	return sharedInstance;
}

- (id) init
{
    do
    {
        self = [super init] ;
        
        if ( !self )
        {
            break ;
        }

        m_dicSecurityGuides =  [self createSecurityGuides] ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (NSDictionary *) createSecurityGuides;
{
    NSDictionary *dicRet = nil ;
    
    do
    {
        if ( m_dicSecurityGuides )
        {
            break ;
        }
        
        NSDictionary *dicSecurityGuides = [self getSecurityPolicyRootFlare: @"Security Guides"] ;
        
        if ( !dicSecurityGuides )
        {
            break ;
        }
        
        NSMutableDictionary *dicWorkGuides = [[NSMutableDictionary alloc] init] ;
        
        if ( !dicWorkGuides )
        {
            break ;
        }
        
        for ( NSString *szGuides in dicSecurityGuides )
        {
            NSDictionary *dicGuides = [dicSecurityGuides objectForKey: szGuides] ;
            
            if ( !dicGuides )
            {
                continue ;
            }
            
            CSecurityGuide *secGuide = nil ;
            
            @try
            {
                secGuide = [[CSecurityGuide alloc] init];
                secGuide.m_szName = szGuides;
                secGuide.m_szCategory = [dicGuides objectForKey: @"Category"];
                secGuide.m_szDescription = [dicGuides objectForKey: @"Description"];
                secGuide.m_aSignatures = [dicGuides objectForKey: @"Signatures"];
            }
            @catch (NSException *exception)
            {
                [ CLog xlogv: @"Exception occurred : %@", [exception reason] ] ;
                secGuide = nil ;
            }
            
            if ( !secGuide )
            {
                continue ;
            }
            
            [dicWorkGuides setObject: secGuide forKey: szGuides] ;
        }
        
        m_dicSecurityGuides = [NSDictionary dictionaryWithDictionary: dicWorkGuides], [m_dicSecurityGuides retain] ;
        
    } while ( _PASSING_ ) ;
    
    dicRet = m_dicSecurityGuides ;
    
    return dicRet ;
}

- (NSString *) getPolicyPath
{
    NSString *szPolicyPath = [ [NSBundle bundleForClass:[self class] ] pathForResource: @"SecurityPolicy" ofType: @"plist"] ;
    
    return szPolicyPath ;
}

- (id) getSecurityPolicyRootFlare: (NSString *)szName
{
    NSString *szPolicyPath = [self getPolicyPath] ;
    id idFlare = nil ;
    
    do
    {
        // nil or empty
        if ( [szPolicyPath length] == 0 )
        {
            break ;
        }
        
        // Root
        NSDictionary *dicRoot = [NSDictionary dictionaryWithContentsOfFile: szPolicyPath] ;
        
        if ( !dicRoot )
        {
            break ;
        }
        
        idFlare = [dicRoot objectForKey: szName] ;
        
    } while ( _PASSING_ ) ;
    
    return idFlare ;
}


- (CSecurityGuide *)detect:(NSString*) string
{
    NSArray *aSigs;
    CSecurityGuide *bSecGuide = nil;
    
    for (id obj in [m_dicSecurityGuides allKeys])
    {
        CSecurityGuide *secGuide = [m_dicSecurityGuides objectForKey:obj];
        aSigs = secGuide.m_aSignatures;
            
        if (!aSigs)
        {
            break;
        }
            
        if ([self stringMatch:string withSignatures:aSigs])
        {
            bSecGuide = secGuide;
            break;
        }
    }
    
    return bSecGuide;
        
}

- (BOOL)stringMatch:(NSString *) string withSignatures: (NSArray *) signatures
{
    BOOL bRet = FALSE;
    
    for (NSString *sig in signatures)
    {
        if ([string isEqualToString:sig]){
            bRet = TRUE;
            break;
            
        }
    }
    
    return bRet;
}


- (void)addSecurityGuide:(CSecurityGuide *)secGuide
{
    if (!self.webview)
        return;
    
    [[self.webview windowScriptObject] setValue:self forKey:@"objcConnector"];
    
    DOMDocument *domDoc = [[self.webview mainFrame] DOMDocument];
    DOMNodeList *tbodys = [domDoc getElementsByTagName:@"tbody"];
    DOMNode *tbody = [tbodys item:0];
    DOMNode *targetTr = [domDoc getElementById:@"Discussion"];
    if (targetTr == nil){
        targetTr = [domDoc getElementById:@"Abstract"];
    }
    DOMNode *nextTrAbstract = [targetTr nextSibling];
    
    // Create a new HTML element
    DOMHTMLElement *tr = (DOMHTMLElement *)[domDoc createElement:@"tr"];
    
    NSString *innerHTMLStr;
    
    NSString *tmpStr1 = @"<th id=\"SecurityGuide\" scope=\"row\">Security Guide</th><td> <font color=\"red\">";
    innerHTMLStr = [tmpStr1 stringByAppendingString:secGuide.m_szDescription];
    
    //Aparently, we need to use a dummy url for this.
    NSString *tmpStr2 = @" <a href=\"http://dummy/\" onClick=\"window.objcConnector.elementClicked_('";
    innerHTMLStr = [innerHTMLStr stringByAppendingString:tmpStr2];
    
    NSDictionary *dicCategories = [CVulnController getVulnCategories];
    CVulnCategory *vulnCategory = [dicCategories objectForKey:secGuide.m_szCategory];
    innerHTMLStr = [innerHTMLStr stringByAppendingString:[vulnCategory getReferencesAt:@"OWASP"][0]];
    
    NSString *tmpStr3 = @"')\"><u>Reference</u></a></td>";
    innerHTMLStr = [innerHTMLStr stringByAppendingString:tmpStr3];
    
    [tr setInnerHTML:innerHTMLStr];
    [tr setClassName:@"slice"];
    
    // Add the element to the container div
    [tbody appendChild:tr];
    [tbody insertBefore:tr refChild:nextTrAbstract];
    
    
}

+ (BOOL)isSelectorExcludedFromWebScript:(SEL)aSelector{
    if (aSelector == @selector(elementClicked:)) return NO;
    return YES;
}

-(void)elementClicked:(id)url{
    [CLog xlog:@"elementClicked: " withObject:url];
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:url]];
}
@end
