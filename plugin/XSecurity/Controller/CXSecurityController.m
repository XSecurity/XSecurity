//
//  XSecurityController.m
//  XSecurity
//
//  Created by Tokuji Akamine on 12/10/13.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CXSecurityController.h"
#import "CLog.h"
#import "XSecDefs.h"
#import "CSecurityScanController.h"
#import "CStaticAnalyzerController.h"
#import "Xcode3UI.h"

@implementation CXSecurityController
+ (void)initialize
{
    [CLog xlog: @"XSecurityController initialized!"] ;
    
    //Set up menu items
    CMenuController *menuController = [[CMenuController alloc] init];
    [menuController setMenu];
}

//- (id) init
//{
//    do
//    {
//        self = [super init] ;
//        
//        if ( !self )
//        {
//            break ;
//        }
//        
//        [Log xlog: @"XSecurityController initialized!"] ;
//        
//        //Set up menu items
//        MenuController *menuController = [[MenuController alloc] init];
//        [menuController setMenu];
//        
//        
//    } while ( _PASSING_ ) ;
//    
//    return self ;
//}

- (void)addNotificationObserver
{
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(quickSecurityHelpDidActivate:) name:@"XSecurityQuickSecurityHelpActivation" object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(quickSecurityHelpDidDeactivate:) name:@"XSecurityQuickSecurityHelpDeactivation" object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(securityScanActivate:) name:@"XSecuritySecurityScanActivation" object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(securityScanDeactivate:) name:@"XSecuritySecurityScanDeactivation" object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(staticAnalyzerRules:) name:@"XSecurityStaticAnalyzerRules" object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(staticAnalyzerAnalyze:) name:@"XSecurityStaticAnalyzerAnalyze" object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(getNotification:) name:nil object:nil];
}

- (void)quickSecurityHelpDidActivate:(NSNotification*) notification
{
    CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter];
    quickHelpController.activationStatus = TRUE;
    
    NSWindowController *currentWindowController = [[NSApp keyWindow] windowController];
    
    if ([currentWindowController isKindOfClass:NSClassFromString(@"IDEWorkspaceWindowController")]) {
        
        IDEWorkspaceTabController *tabController = [(IDEWorkspaceWindowController *)currentWindowController activeWorkspaceTabController];
        quickHelpController.bIsUtilityAreaVisible = [tabController isUtilitiesAreaVisible];
    }
    
}

- (void)quickSecurityHelpDidDeactivate:(NSNotification*) notification
{
    CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter];
    quickHelpController.activationStatus = FALSE;
}

- (void)securityScanActivate:(NSNotification*) notification
{
    CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter];
    securityScanController.activationStatus = TRUE;
    [securityScanController initVulnController];
    
    if (![self lastActiveEditor])
        return;
    
    [securityScanController doScan:(IDESourceCodeDocument *)[self lastActiveEditor].document];
}

- (void)securityScanDeactivate:(NSNotification*) notification
{
    CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter];
    securityScanController.activationStatus = FALSE;
    
    [securityScanController removeAnnotations];
}

- (void)staticAnalyzerRules:(NSNotification*) notification
{
    //CStaticAnalyzerController *staticAnalyzerController = [CStaticAnalyzerController sharedCenter];

}

- (void)staticAnalyzerAnalyze:(NSNotification*) notification
{
    CStaticAnalyzerController *staticAnalyzerController = [CStaticAnalyzerController sharedCenter];
    [staticAnalyzerController analyze];
}

- (void)getNotification:(NSNotification*) notification
{
    if ([notification.name isEqualToString:@"WebProgressFinishedNotification"]){
        
        CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter];
        if (!quickHelpController.activationStatus)
            return;
        
        WebView *webview = notification.object;
        if([webview.superview isMemberOfClass:NSClassFromString(@"DVTControllerContentView")]
            || [webview.superview isMemberOfClass:NSClassFromString(@"NSView")]){
                [self quickHelpContentChanged:notification withWebView:webview];
        }
        
    } else if ([notification.name isEqualToString:@"DVTSourceExpressionSelectedExpressionDidChangeNotification"]){
        
        CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter];
        if (!quickHelpController.activationStatus)
            return;
        
        NSWindowController *currentWindowController = [[NSApp keyWindow] windowController];
        if (![currentWindowController isKindOfClass:NSClassFromString(@"IDEWorkspaceWindowController")])
            return;
        
        IDESourceCodeEditor *sourceCodeEditor = notification.object;
        NSString *symbolString = sourceCodeEditor.selectedExpression.symbolString;
        
        IDEWorkspaceTabController *tabController = [[[NSApp keyWindow] windowController] activeWorkspaceTabController];
        
        if (symbolString == NULL){
            // Hide the utilitityArea if it is not shown at first
            if ([tabController isUtilitiesAreaVisible] && quickHelpController.bIsUtilityAreaVisible != TRUE)
                [tabController hideUtilitiesArea:nil];
            return;
        }
        
        // Obtain a menu [View]->[Utilities]->[Show Quick Help Inspector]
        // ToDo: Need to confirm if the menu which we choose is correct
        NSMenu *mainMenu = [NSApp mainMenu];
        NSArray *menus = mainMenu.itemArray;
        NSMenuItem *menuView = menus[3];
        NSMenuItem *menuUtilities = menuView.submenu.itemArray[6];
        NSMenuItem *menuQuickHelp = menuUtilities.submenu.itemArray[1];
        
        CSecurityGuide *secGuide = nil;
        secGuide = [quickHelpController detect: symbolString];
        
        // If the symbolString matchs with our security guides, then show Quick Help Inspector.
        if (secGuide != nil) {
            [tabController showInspectorWithChoiceFromSender:menuQuickHelp];
            [sourceCodeEditor takeFocus];

        } else {
            // Hide the utilitityArea if it is not shown at first
            if (!quickHelpController.bIsUtilityAreaVisible)
                [tabController hideUtilitiesArea:nil];
        }
        
    } else if ([notification.name isEqualToString:@"IDESourceCodeDocumentDidUpdateSourceModelNotification"]) {
        
        CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter];
        if (securityScanController.activationStatus)
            [securityScanController doScan:notification.object];
        
    } else if ([notification.name isEqualToString:@"transition from one file to another"]) {
        
        CSecurityScanController *securityScanController = [CSecurityScanController sharedCenter];
        if (!securityScanController.activationStatus)
            return;
        
        NSDictionary *dFileTranstion = notification.object;
        
        DVTTextDocumentLocation *documentLocation = [dFileTranstion objectForKey:@"next"];
        NSURL *documentURL = documentLocation.documentURL;
        
        // Currently only support implementation files
        if (![[documentURL pathExtension] isEqualToString:@"m"])
            return;
        
        NSWindowController *currentWindowController = [[NSApp keyWindow] windowController];
        if (![currentWindowController isKindOfClass:NSClassFromString(@"IDEWorkspaceWindowController")])
            return;
        
        IDEWorkspaceWindowController *workspaceWindowController = (IDEWorkspaceWindowController *)currentWindowController;
        IDEEditorContext *editorContext = [[workspaceWindowController editorArea] lastActiveEditorContext];
        IDESourceCodeDocument *document = (IDESourceCodeDocument *)[editorContext editor].document;
        
        if (document)
            [securityScanController doScan:document];
        
    } else if ([notification.name isEqualToString:@"IDEBuildOperationDidStopNotification"]) {
        
        CStaticAnalyzerController *staticAnalyzerController = [CStaticAnalyzerController sharedCenter];
        
        if (staticAnalyzerController.bRunning)
            [staticAnalyzerController finishAnalysis];
        
    }
    
}

- (void) quickHelpContentChanged:(NSNotification*) notification withWebView:(WebView*) webview
{
    if (![[self lastActiveEditor] isKindOfClass:NSClassFromString(@"IDESourceCodeEditor")])
        return;
    
    //Obtain the current editor's textView
    NSTextView *textView = [self lastActiveEditor].textView;
        
    [CLog xlog:@"selectedExpression: " withObject:[self lastActiveEditor].selectedExpression];
    NSString *symbolString = [self lastActiveEditor].selectedExpression.symbolString;
        
    if (![textView isKindOfClass:NSClassFromString(@"DVTSourceTextView")])
        return;
        
    CQuickHelpController *quickHelpController = [CQuickHelpController sharedCenter];
    CSecurityGuide *secGuide = [quickHelpController detect: symbolString];
    if (!secGuide)
        return;
            
    quickHelpController.webview = webview;
    [quickHelpController addSecurityGuide: secGuide];
}

// Obtain the current editor
- (IDESourceCodeEditor *) lastActiveEditor
{
    NSWindowController *currentWindowController = [[NSApp keyWindow] windowController];
    
    if ([currentWindowController isKindOfClass:NSClassFromString(@"IDEWorkspaceWindowController")]) {
        IDEWorkspaceWindowController *workspaceWindowController = (IDEWorkspaceWindowController *)currentWindowController;
        IDEEditorContext *editorContext = [[workspaceWindowController editorArea] lastActiveEditorContext];
        
        return (IDESourceCodeEditor *)[editorContext editor];
    }
    
    return nil;
}

- (NSView *)findSubView:(NSView *)view withClass:(Class)class
{
    if ([view isKindOfClass:class])
        return view;
    
    for (NSView *v in view.subviews) {
        NSView *subview = [self findSubView:v withClass:class];
        if (subview)
            return subview;
    }
    return nil;
}





@end
