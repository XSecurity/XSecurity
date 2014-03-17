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

@implementation CMenuController
- (void)setMenu
{
    // Create a new menu and add new items
    NSMenuItem* menuBarItem = [[NSMenuItem alloc]
                               initWithTitle:@"XSecurity" action:NULL keyEquivalent:@""];
    
    NSMenu* newMenu = [[NSMenu alloc] initWithTitle:@"XSecurity"];
    
    [menuBarItem setSubmenu:newMenu];
    [[NSApp mainMenu] insertItem:menuBarItem atIndex:11]; // Index 11 is after the "Window" item
    

    /*
    NSMenuItem* newItem = [[NSMenuItem alloc] initWithTitle:@"Scan" action:@selector(doMenuAction) keyEquivalent:@""];
    [newItem setTarget:self];
    [newMenu addItem:newItem];
    */
    NSMenuItem* newItem;

    // For some reason this should be in this location to work.
    // For some reason as well, sometimes this work, sometimes not, maybe build should be done first before run, or
    // should quit the new instance of Xcode

// START TEMP: Temporarily removing these lines to remove from the menu
// TODO: Figure out to make local predefines
    newItem = [[NSMenuItem alloc] initWithTitle:@"Raymund Test" action:@selector(doMenuActionRaymund) keyEquivalent:@""];
    [newItem setTarget:self];
    [newMenu addItem:newItem];
// END TEMP
    
    // Add submenus for Quick Security Help
    newMenu = [[NSMenu alloc] initWithTitle:@"Quick Security Help"];
    NSMenuItem *newSubItem1 = [[NSMenuItem alloc] initWithTitle:@"Activate" action:@selector(doQuickSecurityHelpActivate) keyEquivalent:@""];
    [newSubItem1 setTarget:self];
    [newMenu addItem:newSubItem1];
    
    NSMenuItem *newSubItem2 = [[NSMenuItem alloc] initWithTitle:@"Deactivate" action:@selector(doQuickSecurityHelpDeactivate) keyEquivalent:@""];
    [newSubItem2 setTarget:self];
    [newMenu addItem:newSubItem2];
    
    newItem = [[NSMenuItem alloc] initWithTitle:@"Quick Security Help" action:NULL keyEquivalent:@""];
    [newItem setSubmenu:newMenu];
    
    
    //[newMenu setAutoenablesItems:YES];
    
    
    // This seems to be the actual addition of the entire menu being created above
    NSMenuItem *newItem2 = [[NSApp mainMenu] itemWithTitle:@"XSecurity"];
    [[newItem2 submenu] addItem:newItem];
    
    
    // Add submenus for Realtime Security Scanner
    newMenu = [[NSMenu alloc] initWithTitle:@"Security Scanner"];
    NSMenuItem *newSubItem3 = [[NSMenuItem alloc] initWithTitle:@"Activate" action:@selector(doSecurityScanActivate) keyEquivalent:@""];
    [newSubItem3 setTarget:self];
    [newMenu addItem:newSubItem3];
    
    NSMenuItem *newSubItem4 = [[NSMenuItem alloc] initWithTitle:@"Deactivate" action:@selector(doSecurityScanDeactivate) keyEquivalent:@""];
    [newSubItem4 setTarget:self];
    [newMenu addItem:newSubItem4];
    
    newItem = [[NSMenuItem alloc] initWithTitle:@"Vulnerability Notifications" action:NULL keyEquivalent:@""];
    [newItem setSubmenu:newMenu];
    
    
    [newMenu setAutoenablesItems:YES];
    

    NSMenuItem *newItem3 = [[NSApp mainMenu] itemWithTitle:@"XSecurity"];
    [[newItem3 submenu] addItem:newItem];
    
    
    // Add submenus for Static Security Analyzer
    newMenu = [[NSMenu alloc] initWithTitle:@"Static Security Analyzer"];
    /*
    NSMenuItem *newSubItem5 = [[NSMenuItem alloc] initWithTitle:@"Rules..." action:@selector(doStaticAnalyzerRules) keyEquivalent:@""];
    [newSubItem5 setTarget:self];
    [newMenu addItem:newSubItem5];
    
    [newMenu addItem:[NSMenuItem separatorItem]];
     */

    
    NSMenuItem *newSubItem6 = [[NSMenuItem alloc] initWithTitle:@"Analyze" action:@selector(doStaticAnalyzerAnalyze) keyEquivalent:@""];
    [newSubItem6 setTarget:self];
    [newMenu addItem:newSubItem6];
    
    newItem = [[NSMenuItem alloc] initWithTitle:@"Static Security Analyzer" action:NULL keyEquivalent:@""];
    [newItem setSubmenu:newMenu];
    
    
    [newMenu setAutoenablesItems:YES];
    
    
    NSMenuItem *newItem4 = [[NSApp mainMenu] itemWithTitle:@"XSecurity"];
    [[newItem4 submenu] addItem:newItem];
    
}

- (void)doQuickSecurityHelpActivate
{
        [CLog xlog:@"Quick Security Help is activated."];
        NSNotification *quickSecurityHelpActivateNotification = [NSNotification notificationWithName:@"XSecurityQuickSecurityHelpActivation" object:self];
        [[NSNotificationCenter defaultCenter] postNotification:quickSecurityHelpActivateNotification];
}

- (void)doQuickSecurityHelpDeactivate
{
        [CLog xlog:@"Quick Security Help is deactivated."];
        NSNotification *quickSecurityHelpDeactivateNotification = [NSNotification notificationWithName:@"XSecurityQuickSecurityHelpDeactivation" object:self];
        [[NSNotificationCenter defaultCenter] postNotification:quickSecurityHelpDeactivateNotification];
}

- (void)doSecurityScanActivate
{
    [CLog xlog:@"Realtime Security Scan is activated."];
    NSNotification *securityScanActivateNotification = [NSNotification notificationWithName:@"XSecuritySecurityScanActivation" object:self];
    [[NSNotificationCenter defaultCenter] postNotification:securityScanActivateNotification];
}

- (void)doSecurityScanDeactivate
{
    [CLog xlog:@"Realtime Security Scan is deactivated."];
    NSNotification *securityScanDeactivateNotification = [NSNotification notificationWithName:@"XSecuritySecurityScanDeactivation" object:self];
    [[NSNotificationCenter defaultCenter] postNotification:securityScanDeactivateNotification];
}

- (void)doStaticAnalyzerRules
{
    
}

- (void)doStaticAnalyzerAnalyze
{
    [CLog xlog:@"Analyzing the code with Clang Static Analyzer."];
    NSNotification *staticAnalyzerAnalyzeNotification = [NSNotification notificationWithName:@"XSecurityStaticAnalyzerAnalyze" object:self];
    [[NSNotificationCenter defaultCenter] postNotification:staticAnalyzerAnalyzeNotification];
}



- (BOOL) validateMenuItem:(NSMenuItem *)menuItem
{
	SEL menuAction = [menuItem action];
    
	if (menuAction == @selector(doQuickSecurityHelpDeactivate)) {
        
		//CQuickSecurityHelp *quickSecurityHelp = [CQuickSecurityHelp sharedCenter];
        CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter];
        //if (quickSecurityHelp.activationStatus) {
        if (quickHelpController.activationStatus) {
			return YES;
        } else {
            return NO;
        }
        
	} else if (menuAction == @selector(doQuickSecurityHelpActivate)) {
        
		//CQuickSecurityHelp *quickSecurityHelp = [CQuickSecurityHelp sharedCenter];
        CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter];
        //if (quickSecurityHelp.activationStatus) {
        if (quickHelpController.activationStatus) {
			return NO;
        } else {
            return YES;
        }
        
	} else if (menuAction == @selector(doSecurityScanActivate)) {
        
        CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter];
        if (securityScanController.activationStatus) {
			return NO;
        } else {
            return YES;
        }
        
	} else if (menuAction == @selector(doSecurityScanDeactivate)) {
        
        CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter];
        if (securityScanController.activationStatus) {
			return YES;
        } else {
            return NO;
        }
        
    } else if (menuAction == @selector(doStaticAnalyzerAnalyze)) {
        
        //CStaticAnalyzerController *staticAnalyzerController = [CStaticAnalyzerController sharedCenter];
        if ([[[NSApp keyWindow] className] isEqualToString:@"IDEWorkspaceWindow"]) {
			return YES;
        } else {
            return NO;
        }
        
    }
    
 	return YES; // return YES here so all other menu items will be displayed
}

// Temporary implementation, I expect this to go through XSecurityController
//
- (void) doMenuActionRaymund
{
    [CLog xlog:@" doMenuActionRaymund called!"];
    
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
