//
//  MenuController.m
//  XSecurity
//
//  Created by Tokuji Akamine on 12/10/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CMenuController.h"
#import "CLog.h"
#import "CXSecurityController.h"
#import "CSecurityScanController.h"
#import "CStaticAnalyzerController.h"

//Temporary
#import "CVulnController.h"
#import "XSecDefs.h"

    // For some reason this should be in this location to work.
    // For some reason as well, sometimes this work, sometimes not, maybe build should be done first before run, or
    // should quit the new instance of Xcode
    
// START TEMP: Temporarily removing these lines to remove from the menu
// TODO: Figure out to make local predefines
//    newItem = [[NSMenuItem alloc] initWithTitle:@"Raymund Test" action:@selector(doMenuActionRaymund) keyEquivalent:@""] ;
//    [newItem setTarget:self] ;
//    [objMenu addItem:newItem] ;
// END TEMP

@implementation CMenuController

- (void)setMenu
{
    //
    // Create a new menu and add new items
    //
    NSMenuItem *menuBarItem = [[NSMenuItem alloc] initWithTitle:@"XSecurity" action:NULL keyEquivalent:@""] ;
    NSMenu *objXSecurityMenu = [[NSMenu alloc] initWithTitle:@"XSecurity"] ;
   
    // Make the item drop-down a submenu
    [menuBarItem setSubmenu:objXSecurityMenu] ;
    
    [[NSApp mainMenu] insertItem: menuBarItem atIndex: 11] ; // Index 11 is before the "Window" item
    
    //
    // Add submenus for Quick Security Help
    //
    
    NSMenuItem *objXSecItem = [[NSMenuItem alloc] initWithTitle: @"Quick Security Help" action:NULL keyEquivalent:@""] ;
    NSMenu     *objSubMenu  = [[NSMenu alloc] initWithTitle:     @"Quick Security Help"] ;
   
    // Make the item drop-down a submenu
    [objXSecItem setSubmenu: objSubMenu] ;

    // Add activate item
    NSMenuItem *objActivateItem = [[NSMenuItem alloc] initWithTitle: @"Activate" 
                                                      action:        @selector(doQuickSecurityHelpActivate) 
                                                      keyEquivalent: @""] ;
    [objActivateItem setTarget: self] ;
    [objSubMenu addItem: objActivateItem] ;
    
    
    // Add deactivate item
    NSMenuItem *objDeactivateItem = [[NSMenuItem alloc] initWithTitle: @"Deactivate" 
                                                        action:        @selector(doQuickSecurityHelpDeactivate) 
                                                        keyEquivalent: @""] ;
    [objDeactivateItem setTarget: self] ;
    [objSubMenu addItem: objDeactivateItem] ;
   
    // Add Quick Secutity Help item to XSecurity Menu
    [objXSecurityMenu addItem: objXSecItem] ;

    //
    // Add submenus for Realtime Vulnerability Notification
    //
    
    // Not a good idea but just recycle objSubMenu, objXSecItem, objActivateItem & objDeactivateItem
    objXSecItem = [[NSMenuItem alloc] initWithTitle: @"Vulnerability Notifications" action: NULL keyEquivalent: @""] ;
    objSubMenu  = [[NSMenu alloc] initWithTitle:     @"Vulnerability Notification"] ;

    [objXSecItem setSubmenu: objSubMenu] ;

    objActivateItem = [[NSMenuItem alloc] initWithTitle: @"Activate" 
                                          action:        @selector(doSecurityScanActivate) 
                                          keyEquivalent: @""] ;
   
    [objActivateItem setTarget: self] ;
    [objSubMenu addItem: objActivateItem] ;
    
    
    objDeactivateItem = [[NSMenuItem alloc] initWithTitle: @"Deactivate" 
                                            action:        @selector(doSecurityScanDeactivate) 
                                            keyEquivalent: @""] ;

    [objDeactivateItem setTarget: self] ;
    [objSubMenu addItem: objDeactivateItem] ;
    
    [objSubMenu setAutoenablesItems: YES] ;

    // Add Vulnerability Notificaiton item to the XSecurity Menu
    [objXSecurityMenu addItem: objXSecItem] ;

    //
    // Add submenus for Static Security Analyzer
    //

    // Again not a good idea but just recycle objSubMenu and objXSecItem 
    objXSecItem = [[NSMenuItem alloc] initWithTitle: @"Static Security Analyzer: Analyze" 
                                      action:        @selector(doStaticAnalyzerAnalyze) 
                                      keyEquivalent: @""] ;

    [objXSecItem setTarget: self] ;
    [objXSecurityMenu addItem: objXSecItem] ;
    
    [objXSecurityMenu setAutoenablesItems: YES] ;
    [objXSecurityMenu addItem: [NSMenuItem separatorItem]] ;

    // Add the current version of the plug-in
    //TODO: Use plist, external file, etc to display version
    objXSecItem = [[NSMenuItem alloc] initWithTitle: @"v0.0.3" action: NULL keyEquivalent: @""] ;
    
    [objXSecurityMenu addItem: objXSecItem] ;
}

- (void)doQuickSecurityHelpActivate
{
    [CLog xlog:@"Quick Security Help is activated."] ;
    NSNotification *quickSecurityHelpActivateNotification = [NSNotification notificationWithName:@"XSecurityQuickSecurityHelpActivation" object:self] ;
    [[NSNotificationCenter defaultCenter] postNotification:quickSecurityHelpActivateNotification] ;
}

- (void)doQuickSecurityHelpDeactivate
{
    [CLog xlog:@"Quick Security Help is deactivated."] ;
    NSNotification *quickSecurityHelpDeactivateNotification = [NSNotification notificationWithName:@"XSecurityQuickSecurityHelpDeactivation" object:self] ;
    [[NSNotificationCenter defaultCenter] postNotification:quickSecurityHelpDeactivateNotification] ;
}

- (void)doSecurityScanActivate
{
    [CLog xlog:@"Realtime Security Scan is activated."] ;
    NSNotification *securityScanActivateNotification = [NSNotification notificationWithName:@"XSecuritySecurityScanActivation" object:self] ;
    [[NSNotificationCenter defaultCenter] postNotification:securityScanActivateNotification] ;
}

- (void)doSecurityScanDeactivate
{
    [CLog xlog:@"Realtime Security Scan is deactivated."] ;
    NSNotification *securityScanDeactivateNotification = [NSNotification notificationWithName:@"XSecuritySecurityScanDeactivation" object:self] ;
    [[NSNotificationCenter defaultCenter] postNotification:securityScanDeactivateNotification] ;
}

- (void)doStaticAnalyzerRules
{
    
}

- (void)doStaticAnalyzerAnalyze
{
    [CLog xlog:@"Analyzing the code with Clang Static Analyzer."] ;
    NSNotification *staticAnalyzerAnalyzeNotification = [NSNotification notificationWithName:@"XSecurityStaticAnalyzerAnalyze" object:self] ;
    [[NSNotificationCenter defaultCenter] postNotification:staticAnalyzerAnalyzeNotification] ;
}



- (BOOL) validateMenuItem:(NSMenuItem *)menuItem
{
	SEL menuAction = [menuItem action] ;
    
	if (menuAction == @selector(doQuickSecurityHelpDeactivate)) {
        
		//CQuickSecurityHelp *quickSecurityHelp = [CQuickSecurityHelp sharedCenter] ;
        CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter] ;
        //if (quickSecurityHelp.activationStatus) {
        if (quickHelpController.activationStatus) {
			return YES ;
        } else {
            return NO ;
        }
        
	} else if (menuAction == @selector(doQuickSecurityHelpActivate)) {
        
		//CQuickSecurityHelp *quickSecurityHelp = [CQuickSecurityHelp sharedCenter] ;
        CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter] ;
        //if (quickSecurityHelp.activationStatus) {
        if (quickHelpController.activationStatus) {
			return NO ;
        } else {
            return YES ;
        }
        
	} else if (menuAction == @selector(doSecurityScanActivate)) {
        
        CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter] ;
        if (securityScanController.activationStatus) {
			return NO ;
        } else {
            return YES ;
        }
        
	} else if (menuAction == @selector(doSecurityScanDeactivate)) {
        
        CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter] ;
        if (securityScanController.activationStatus) {
			return YES ;
        } else {
            return NO ;
        }
        
    } else if (menuAction == @selector(doStaticAnalyzerAnalyze)) {
        
        //CStaticAnalyzerController *staticAnalyzerController = [CStaticAnalyzerController sharedCenter] ;
        if ([[[NSApp keyWindow] className] isEqualToString:@"IDEWorkspaceWindow"]) {
			return YES ;
        } else {
            return NO ;
        }
        
    }
    
 	return YES ; // return YES here so all other menu items will be displayed
}

// Temporary implementation, I expect this to go through XSecurityController
//
- (void) doMenuActionRaymund
{
    [CLog xlog:@" doMenuActionRaymund called!"] ;
    
    do
    {	
        static CVulnController *g_pController = nil ;
        
        if ( !g_pController )
        {
            g_pController = [[CVulnController alloc] init] ;
            [g_pController retain] ;
        }
        
        CTargetCode *objTarget = [ [CTargetCode alloc] initWithFile: @"/Users/raymund.pedraita/Projects/own/xsecurity/XSecurity/test/sample_sensitive.m"] ;
        
        NSArray *aaaRes = [g_pController detect: objTarget bCommentRemoved: FALSE] ;
        
        [g_pController logResults: aaaRes] ;
        
//        [aaaRes release] ;
//        [objTarget release] ;

    } while ( _PASSING_ );

}

@end
