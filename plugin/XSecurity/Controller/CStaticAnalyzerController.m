//
//  CStaticAnalyzerController.m
//  XSecurity
//
//  Created by Tokuji Akamine on 1/22/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CStaticAnalyzerController.h"
#import "IDEKit.h"
#import "IDEFoundation.h"
#import "Xcode3UI.h"
#import "CLog.h"
#import <objc/runtime.h>
#import "XSecDefs.h"

@implementation CStaticAnalyzerController

- (id)init {
    self = [super init];
    if (!self){
        return nil;
    }
    
    self.bRunning = FALSE;
    tmpBuildString = @"";
    tmpPbxTarget = nil;
    key = nil;
    
    return self;
}

+ (id)sharedCenter {
	static CStaticAnalyzerController* sharedInstance = nil;
	if(!sharedInstance) {
		sharedInstance = [[self alloc] init];
	}
	return sharedInstance;
}

- (void)analyze {
    
    IDEWorkspaceTabController *tabController = [[[NSApp keyWindow] windowController] activeWorkspaceTabController];
    NSArray *projects = [tabController.workspaceDocument sdefSupport_projects];
    
    if ([projects count] == 0)
        return;
    
    if (![[projects[0] className] isEqualToString:@"Xcode3ProjectWrapper"])
        return;
    
    Xcode3ProjectWrapper *wrapper = projects[0];
    
    if (![[wrapper.client className] isEqualToString:@"Xcode3Project"])
        return;
    
    Xcode3Project *project = wrapper.client;
    PBXProject *pbxProject = project.pbxProject;
    
    IDEWorkspaceWindowController *currentWindowController = [[NSApp keyWindow] windowController];
    IDEWorkspace *workspace = [currentWindowController valueForKey:@"_workspace"];
    IDERunContextManager *runContextManager = [workspace runContextManager];
    IDEScheme *activeScheme = runContextManager.activeRunContext;
    
    for (PBXNativeTarget *pbxTarget in pbxProject.targets)
    {
        
        if (![[pbxTarget name] isEqualToString:activeScheme.name])
            continue;
        
        if (![currentWindowController isKindOfClass:NSClassFromString(@"IDEWorkspaceWindowController")])
            continue;
        
        tmpBuildString = @"";
        
        [CLog xlog:@"Analysis Target" withObject:[pbxTarget name]];
        
        XCConfigurationList *list = pbxTarget.buildConfigurationList;
        [CLog xlog:@"list.buildConfigurationNames: " withObject:list.buildConfigurationNames];
        [CLog xlog:@"list.buildConfigurations: " withObject:list.buildConfigurations];
        
        XCBuildConfiguration *configuration = list.buildConfigurations[0]; //Choose Debug Configuration
        [CLog xlog:@"configuration.buildSettings: " withObject:configuration.buildSettings];
        [CLog xlog:@"[pbxtarget allBuildSettingNamesWithBuildParameters:nil]): " withObject:[pbxTarget allBuildSettingNamesWithBuildParameters:nil]];
        
        for (NSString *buildSettingString in [configuration.buildSettings valueForKey:@"WARNING_CFLAGS"])
        {
            tmpBuildString = [tmpBuildString stringByAppendingString:buildSettingString];
            tmpBuildString = [tmpBuildString stringByAppendingString:@" "];
        }
        
        objc_setAssociatedObject(self, key, tmpBuildString, OBJC_ASSOCIATION_RETAIN);
        
        //Activate our checkers
        [pbxTarget setBuildSetting:_CHECKERS_ forKeyPath:@"WARNING_CFLAGS"];
        
        NSWindowController *currentWindowController = [[NSApp keyWindow] windowController];
        
        IDEWorkspaceWindowController *workspaceWindowController = (IDEWorkspaceWindowController *)currentWindowController;
        IDEEditorContext *editorContext = [[workspaceWindowController editorArea] lastActiveEditorContext];
        
        tmpPbxTarget = pbxTarget;
        
        // Start analyzing ...
        self.bRunning = TRUE;
        [tabController analyzeActiveRunContext:editorContext];
    }
}

- (void)finishAnalysis
{
    if (![tmpPbxTarget.name isEqualToString:tmpPbxTarget.name])
        return;
    
    tmpBuildString = objc_getAssociatedObject(self, key);
    [tmpPbxTarget setBuildSetting:tmpBuildString forKeyPath:@"WARNING_CFLAGS"];
    
    tmpPbxTarget = nil;
    self.bRunning = FALSE;
    
}

@end
