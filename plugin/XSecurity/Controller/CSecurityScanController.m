//
//  CSecurityScanController.m
//  XSecurity
//
//  Created by Tokuji Akamine on 1/21/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import "CSecurityScanController.h"
#import "CVulnController.h"
#import "CVulnerability.h"
#import "CKeywordVuln.h"
#import "CPureKeywordVuln.h"
#import "CKeywordCallerVuln.h"
#import "CResult.h"
#import "NSAttributedString+Hyperlink.h"
#import "DVTKit.h"
#import "CVulnCategory.h"

@interface CSecurityAnnotation : DVTMessageBubbleAnnotation
@property (nonatomic, retain)CVulnerability *vuln;
@end

@implementation CSecurityAnnotation
@end

@implementation CSecurityScanController

+ (id)sharedCenter {
	static CSecurityScanController* sharedInstance = nil;
	if(!sharedInstance) {
		sharedInstance = [[self alloc] init];
	}
	return sharedInstance;
}

- (void)initVulnController
{
    m_vulnController = [[CVulnController alloc] init];
}

- (void)doScan:(IDESourceCodeDocument *)document
{
    dispatch_queue_t main_queue = dispatch_get_main_queue();
    dispatch_queue_t sub_queue = dispatch_queue_create("org.xsecurity", 0);
    
    dispatch_async(sub_queue, ^{
        
        DVTTextStorage *textStorage = document.textStorage;
        
        if ([document._documentEditors count] == 0) // Currently not supporting the Assistant Editor
            return;
        
        if (![[document._documentEditors anyObject] isMemberOfClass:NSClassFromString(@"IDESourceCodeEditor")])
            return;
        
        CTargetCode *objTarget = [[CTargetCode alloc] initWithData:[textStorage string]];
        
        NSArray *aaaRes = [m_vulnController detect:objTarget bCommentRemoved:FALSE];
        
        //[m_vulnController logResults: aaaRes];
        
        dispatch_async(main_queue, ^{
            [self scanFinished:document withResults:aaaRes];
        });
        
    });
    
}

- (void)scanFinished:(IDESourceCodeDocument *)targetDocument withResults:(NSArray* )aaaRes
{
    IDESourceCodeDocument *document = [self currentDocument];
    if (!document)
        return;
    
    if (document != targetDocument)
        return;
    
    IDESourceCodeEditor *editor = [document._documentEditors anyObject];
    DVTSourceTextView *sourceTextView = (DVTSourceTextView *)editor.textView;
    DVTLayoutManager *layoutManager = sourceTextView.layoutManager;
    
    DVTTextStorage *textStorage = document.textStorage;
    
    // Remove the current annotations
    NSArray *annotations = [[layoutManager annotations] copy];
    if ([annotations count])
        for (id annotation in annotations){
            if ([annotation isMemberOfClass:NSClassFromString(@"CSecurityAnnotation")]) {
                [layoutManager removeAnnotation:annotation];
            }
        }
    
    
    for (NSArray *aaRes in aaaRes) {
        
        for (NSArray *aRes in aaRes) {
            
            for (CResult *result in aRes) {
                
                CVulnerability *vuln = [result getVulnerability];
                
                DVTTextDocumentLocation *documentLocation = [editor _documentLocationForLineNumber:[sourceTextView _currentLineNumber]];
                NSURL *documentUrl = documentLocation.documentURL;
                
                CSecurityAnnotation *myAnnotation = [[CSecurityAnnotation alloc] init];
                myAnnotation.delegate = self;
                myAnnotation.vuln = vuln;
                myAnnotation.severity = [vuln getSeverity];
                myAnnotation.messageBubbleText = [vuln getName];
                NSString *filePath = [[NSBundle bundleForClass:[self class]] pathForResource:@"icon" ofType:@"png"];
                myAnnotation.messageBubbleIcon = [[NSImage alloc] initWithContentsOfFile: filePath];
                myAnnotation.sidebarMarkerImage = [[NSImage alloc] initWithContentsOfFile: filePath];
                myAnnotation.location = [[DVTTextDocumentLocation alloc] initWithDocumentURL:documentUrl timestamp:NULL lineRange:[textStorage lineRangeForCharacterRange: NSMakeRange([result getRange].location - 1, [result getRange].length)]];
                [myAnnotation setVisible: TRUE];
                
                [layoutManager addAnnotation: myAnnotation];
            }
            
        }
        
    }
    
}

// Remove all annotations from the current document
- (void)removeAnnotations
{
    IDESourceCodeDocument *document = [self currentDocument];
    if (!document)
        return;
    
    IDESourceCodeEditor *editor = [document._documentEditors anyObject];
    
    DVTSourceTextView *sourceTextView = (DVTSourceTextView *)editor.textView;
    DVTLayoutManager *layoutManager = sourceTextView.layoutManager;
    
    NSArray *annotations = [[layoutManager annotations] copy];
    if ([annotations count])
        for (id annotation in annotations){
            if ([annotation isMemberOfClass:NSClassFromString(@"CSecurityAnnotation")]) {
                [layoutManager removeAnnotation:annotation];
            }
        }
}

// Obtain the current document
- (IDESourceCodeDocument *)currentDocument
{
    NSWindowController *currentWindowController = [[NSApp keyWindow] windowController];
    
    if (![currentWindowController isKindOfClass:NSClassFromString(@"IDEWorkspaceWindowController")])
        return nil;
    
    IDEWorkspaceWindowController *workspaceWindowController = (IDEWorkspaceWindowController *)currentWindowController;
    IDEEditorContext *editorContext = [[workspaceWindowController editorArea] lastActiveEditorContext];
    IDESourceCodeDocument *document = (IDESourceCodeDocument *)[editorContext editor].document;
    
    if ([document._documentEditors count] == 0) // Currently not supporting the Assistant Editor
        return nil;
    
    if (![[document._documentEditors anyObject] isMemberOfClass:NSClassFromString(@"IDESourceCodeEditor")])
        return nil;
    
    return document;
}

// DVTTextAnnotation Delegate Method
- (void)didClickAnnotation:(id)arg1 inTextSidebarView:(id)arg2 event:(id)arg3
{
    [CLog xlog:@"An annotation is clicked." withObject:arg1];
    
    [self showSecurityGuide: (CSecurityAnnotation *)arg1];
    
}

- (void)didClickMessageBubbleForAnnotation:(id)arg1 onIcon:(BOOL)arg2 inTextView:(id)arg3 event:(id)arg4
{
    [CLog xlog:@"A message bubble annotation is clicked." withObject:arg1];
    
    [self showSecurityGuide:(CSecurityAnnotation *)arg1];
}

- (void) showSecurityGuide:(CSecurityAnnotation *)annotation
{
    [CLog xlog:@"Show a security guide for the annotation." withObject:annotation];
    
    if ([self viewClickerController] == nil) {
		[self setViewClickerController:[[[CSecurityGuideWindowController alloc] init] autorelease]];
	}
    
	[[self viewClickerController] showWindow:[NSApp mainWindow]];
    
    NSWindow *window = [self viewClickerController].window;
    
    NSTextView *securityGuideTextView = nil;
    
    for(id obj in [self allSubviewsOfView:[window contentView]]){
        if ([obj isMemberOfClass:NSClassFromString(@"NSTextView")]) {
            securityGuideTextView = obj;
        }
    }
    
    // Prepare a security guide for the issue
    [securityGuideTextView setString:@"\nIssue Overview:\n "];
    NSString *tmpstr = [[annotation.vuln getName] stringByAppendingString:@" \n\nSource:\n "];
    NSAttributedString* atrstr = [[[NSAttributedString alloc] initWithString:tmpstr] autorelease];
    [securityGuideTextView.textStorage appendAttributedString: atrstr];
    
    tmpstr = [[annotation.location.documentURL lastPathComponent] stringByAppendingString:@": "];
    tmpstr = [tmpstr stringByAppendingString:[NSString stringWithFormat: @"%ld", (unsigned long)annotation.location.lineRange.location + 1]];
    atrstr = [[[NSAttributedString alloc] initWithString:tmpstr] autorelease];
    [securityGuideTextView.textStorage appendAttributedString: atrstr];
    
    tmpstr = [@"\n\nDescription:\n " stringByAppendingString:[annotation.vuln getDescription]];
    atrstr = [[[NSAttributedString alloc] initWithString:tmpstr] autorelease];
    [securityGuideTextView.textStorage appendAttributedString: atrstr];
    
    NSString *severity = nil;
    switch ([annotation.vuln getSeverity]) {
        case E_SEVERITY_WARN:
            severity = @"WARNING";
            break;
        case E_SEVERITY_LOW:
            severity = @"LOW";
            break;
        case E_SEVERITY_MID:
            severity = @"MEDIUM";
            break;
        case E_SEVERITY_HIGH:
            severity = @"HIGH";
            break;
        default:
            break;
    }
    
    tmpstr = [@"\n\nSeverity:\n " stringByAppendingString:severity];
    atrstr = [[[NSAttributedString alloc] initWithString:tmpstr] autorelease];
    [securityGuideTextView.textStorage appendAttributedString: atrstr];
    
    NSDictionary *dicCategories = nil;
    dicCategories = [CVulnController getVulnCategories];
    
    if (!dicCategories)
        return;
    
    NSString *categoryName = [[annotation.vuln getCategory] getName];
    CVulnCategory *vulnCategory = nil;
    vulnCategory = [dicCategories objectForKey: categoryName];
    
    if (!vulnCategory)
        return;
    
    atrstr = [[[NSAttributedString alloc] initWithString:@"\n\nReference:\n "] autorelease];
    [securityGuideTextView.textStorage appendAttributedString: atrstr];
    
    NSMutableAttributedString *attributedString = [[NSMutableAttributedString alloc] init];
    NSURL* url = [NSURL URLWithString: [vulnCategory getReferencesAt:@"OWASP"][0]];
    [attributedString appendAttributedString:[NSAttributedString hyperlinkFromString:@" OWASP\n" withURL:url]];
    [[securityGuideTextView textStorage] appendAttributedString:attributedString];
    [attributedString release];
    
    
}

- (NSArray *)allSubviewsOfView:(NSView *)view
{
    NSMutableArray *subviews = [[view subviews] mutableCopy];
    for (NSView *subview in [view subviews])
        [subviews addObjectsFromArray:[self allSubviewsOfView:subview]];
    return subviews;
}

- (NSView *)windowTitleViewForWindow:(NSWindow *)window
{
	NSView *windowFrameView = [[window contentView] superview];
	for (NSView *view in windowFrameView.subviews) {
		if ([view isKindOfClass:NSClassFromString(@"DVTDualProxyWindowTitleView")]) {
			return view;
		}
	}
	return nil;
}

@end
