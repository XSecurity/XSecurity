//
//  CVulnController.m
//  XSecurity
//
//  Created by Pedraita, Raymund on 12/19/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "XSecDefs.h"
#import "CLog.h"

#import "CVulnController.h"
#import "CVulnerability.h"
#import "CKeywordVuln.h"
#import "CPureKeywordVuln.h"
#import "CKeywordCallerVuln.h"
#import "CResult.h"
#import "CSensitiveInfoKeywords.h"

static  NSDictionary *m_dicCategories = nil ;

@implementation CVulnController

+ (CSensitiveInfoKeywords *) createSensitiveInfoKeywordsObject
{
    CSensitiveInfoKeywords *objRet = nil ;
    CVulnController *meObj = [ [[CVulnController alloc] init] autorelease ] ;
    
    do
    {
        if ( !meObj )
        {
            break ;
        }
        
        NSArray *aszKeywords = [meObj getSecurityPolicyRootFlare: @"SensitiveInfoKeywords"] ;
        
        if ( !aszKeywords )
        {
            break ;
        }
        
        objRet = [ [CSensitiveInfoKeywords alloc] initWithKeywords: aszKeywords ] ;
        
        //TODO: See if this breaks something
        [objRet autorelease] ;
        
    } while ( _PASSING_ ) ;

    return objRet ;
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
        m_aVulns        = nil ;
        
        // Divide the load by doing categories here
        m_dicCategories =  [self createVulnCategories] ;
        
    } while ( _PASSING_ ) ;
    
    return self ;
}

- (void) dealloc
{
    [m_aVulns      release], m_aVulns      = nil ;
    [m_dicCategories release], m_dicCategories = nil ;
    
    [super dealloc] ;
}

// If all things are alright this promises a non nil dictionary of categories
+ (NSDictionary *) getVulnCategories
{
    if ( !m_dicCategories )
    {
        //TODO: This looks like a workaround and should be improved in the future.
        CVulnController *pThis = [[CVulnController alloc] init] ;
        
        m_dicCategories = [pThis createVulnCategories] ;
    }
    
    return m_dicCategories ;
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

- (NSDictionary *) createVulnCategories
{
    NSDictionary *dicRet = nil ;
    
    do
    {
        if ( m_dicCategories )
        {
            dicRet = m_dicCategories ;
            break ;
        }
        
        NSDictionary *dicVulnCats = [self getSecurityPolicyRootFlare: @"Vulnerability Categories"] ;
        
        if ( !dicVulnCats )
        {
            break ;
        }
      
        NSMutableDictionary *dicWorkCats = [[NSMutableDictionary alloc] init] ;
        
        if ( !dicWorkCats )
        {
            break ;
        }
        
        for ( NSString *szCat in dicVulnCats )
        {
            NSDictionary *dicCat = [dicVulnCats objectForKey: szCat] ;
            
            if ( !dicCat )
            {
                continue ;
            }
            
            CVulnCategory *objCat = nil ;
            
            @try
            {
                objCat = [ [CVulnCategory alloc] initWithName: szCat eSeverity: (E_SEVERITY )[ [dicCat objectForKey: @"Severity"] intValue]  szDescription: [dicCat objectForKey: @"Description"] dicReferences: [dicCat objectForKey: @"References"] ] ;
            }
            @catch (NSException *exception)
            {
                [ CLog xlogv: @"Exception occurred : %@", [exception reason] ] ;
                objCat = nil ;
            }
            
            if ( !objCat )
            {
                continue ;
            }
            
            [dicWorkCats setObject: objCat forKey: szCat] ;
        }
        
        m_dicCategories = [NSDictionary dictionaryWithDictionary: dicWorkCats], [m_dicCategories retain] ;
        
        dicRet = m_dicCategories ;
        
    } while ( _PASSING_ ) ;

    return dicRet ;
}


// NOTE: Vuln classes should be created only once because the rules is not expected
//       to change at runtime, especially if this class will be disigned as a singleton
//       It may not change at runtime but it is possible to disable it thus it is made mutable
- (NSMutableArray *) createVulnClasses
{
    do
    {
        // non-nil assumes that vulns is already created
        if ( m_aVulns )
        {
            break ;
        }

        NSMutableArray *returnArray = [ [[NSMutableArray alloc] init] autorelease ] ;
        
        if ( !returnArray )
        {
            break ;
        }
        
        NSDictionary *dicRules = [self getSecurityPolicyRootFlare: @"Rules"] ;
        
        if ( !dicRules )
        {
            break ;
        }

        NSDictionary *dicCats = [self createVulnCategories] ;
        
        for ( NSString *szVulnClassName in dicRules )
        {
            // Retrieve dictionary for the current vulnerability class
            NSDictionary *dicVulnClass = [dicRules objectForKey: szVulnClassName] ;
            
            if ( !dicVulnClass )
            {
                continue ;
            }
            
            for ( NSString *szVulnName in dicVulnClass )
            {
                NSDictionary *dicVulnName = [dicVulnClass objectForKey: szVulnName] ;
                
                if ( !dicVulnName )
                {
                    continue ;
                }
                
                CVulnCategory *objCat = [dicCats objectForKey: [dicVulnName objectForKey:@"VulnCategory"]] ;

                id vulnObj =  nil ;
                
                @try
                {
                    vulnObj = [ [NSClassFromString( szVulnClassName ) alloc ] initWithName: szVulnName eSeverity: (E_SEVERITY)[[dicVulnName objectForKey:@"Severity"] intValue] bStripComment: (BOOL)[[dicVulnName objectForKey:@"StripComment"] boolValue] szDescription: [dicVulnName objectForKey:@"Description"] aszReferences:[ dicVulnName objectForKey:@"References"] dicInstances: [ dicVulnName objectForKey:@"Instances"] objCategory: objCat ] ;
                    
                    vulnObj = [vulnObj autorelease] ;
                }
                @catch (NSException *exception)
                {
                    [CLog xlogv: @"Exception, check SecurityPolicy.plist there might be wrong with '%@' - '%@' node", szVulnClassName, szVulnName ] ;
                    continue ;
                }
                
                if ( !vulnObj )
                {
                    continue ;
                }
                
                [returnArray addObject: vulnObj] ;
            }
        }
        
        if ( ![returnArray count] )
        {
            break ;
        }

        m_aVulns = returnArray, [m_aVulns retain] ;
        
        //TEMP : Not really sure if this is alright or not
        //       Retain this as long as possible until this parent class exist
        //[m_aVulns retain] ;

    } while ( _PASSING_ ) ;
    
    return m_aVulns ;
}

// NOTE: Returns a three dimentional array of array of array of CResult
- (NSArray *) detect: (CTargetCode *) objTarget bCommentRemoved: (BOOL) bCommentRemoved ;
{
    NSArray *aaaRet = nil ;
    NSMutableArray *aaaWorkResults = [ [[NSMutableArray alloc] init] autorelease ] ;
    
    
    [CLog xlog: @"Detecting..." ] ;
    
    do
    {
        // Out of memory?
        if ( !aaaWorkResults )
        {
            break ;
        }

        // Reference only
        NSMutableArray  *aVulns = [self createVulnClasses] ;
        
        if ( !aVulns )
        {
            break ;
        }
        
        for ( CVulnerability *objVuln in aVulns )
        {
            NSArray *aaResult = [objVuln detect: objTarget bCommentRemoved: bCommentRemoved] ;
            
            if ( !aaResult )
            {
                continue ;
            }
            
            [aaaWorkResults addObject: aaResult] ;
        }
        
        if ( ![aaaWorkResults count] )
        {
            break ;
        }
        
        aaaRet = [NSArray arrayWithArray: aaaWorkResults] ;
    } while ( _PASSING_ ) ;

    [CLog xlog: @"Done!" ] ;
    return aaaRet ;
}


// NOTE: aaaResults is an array of array of array of CResults
- (void) logResults: (NSArray *)aaaResults
{
    do
    {
        if ( !aaaResults )
        {
            break ;
        }
        
        int iCtr = 0 ;
        
        for ( NSArray *aaVulnResult in aaaResults )
        {
            for ( NSArray *aResult in aaVulnResult )
            {
                for ( CResult *objResult in aResult )
                {
                    [objResult log: ++iCtr] ;
                }
            }
        }
    } while ( _PASSING_ ) ;

}


@end


