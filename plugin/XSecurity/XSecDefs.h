//
//  XSecDefs.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 12/19/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>

#define _PASSING_ (0)

#define _countof( _obj_ ) ( sizeof(_obj_) / (sizeof( typeof( _obj_[0] ))) )

#define _CHECKERS_ (@"-Xanalyzer -analyzer-checker=msec.iosappsec.iOSAppSecInsecureKeyChainStorageChecker,msec.iosappsec.iOSAppSecInsecureNSUserDefaultsUsageChecker,msec.iosappsec.iOSAppSecInsecurePlistUsageChecker,msec.iosappsec.iOSAppSecPermanentCredentialChecker,msec.iosappsec.iOSAppSecIgnoresValidationErrorsChecker,msec.iosappsec.iOSAppSecAbusingURLSchemesChecker,msec.iosappsec.iOSAppSecLeakingWebCachesChecker,msec.iosappsec.iOSAppSecLeakingLogsChecker,msec.iosappsec.iOSAppSecLeakingPasteboardChecker,msec.iosappsec.iOSAppSecSQLInjectionChecker,msec.iosappsec.iOSAppSecBufferOverflowChecker")


