### XSecurity

A security plug-in in Xcode with clang analyzer's checkers for iOS application development. 
This plug-in aims to reduce the vulnerability made during development by detecting the vulnerability 
as it is being created. You can also follow us on twitter: https://twitter.com/prj_xsecurity to get notified of the updates of this tool.

This readme is mainly for the plug-in itself. If you want to contribute and build the checkers, it is best to see
the designated [README](https://github.com/XSecurity/XSecurity/tree/master/checker) first **before cloning this repostory**.

Support Xcode Versions:  
6.1, 5.1.1, 5.1, 5.0.x 4.6.x

Support OS X Versions:  
Mavericks (10.9) , Mountain Lion (10.8)


##### INSTALLATION
_____________________________

- Most of the time this may not be necessary, but to be sure:
In Xcode select the XSecurity Scheme. Go to "Edit Scheme" and set instances of "Build Configuration" to "Release"  
- Clean the build folder of the XSecurity project
  *Execute Alt-Shift-Cmd-K or hold Alt key while selecting  Main Menu -> Product -> Clean
  *In some cases XSecurity plug-in will not work if the build folder is not properly cleaned. 
- Execute build and it will automatically install the plug-in into the correct directory ('~/Library/Application Support/Developer/Shared/Xcode/Plug-ins/').  
- Quit Xcode and start it again. (Make it sure that the Xcode process is fully terminated)  
This time XSecurity will be loaded, you will most likely find a menu item: XSecurity in the main menu. 


##### HOW TO UNINSTALL
_____________________________

Delete the following directory:  
~/Library/Application Support/Developer/Shared/Xcode/Plug-ins/XSecurity.xcplug-in


##### FEATURE LIST
_____________________________

- Developer-friendly security features on Xcode IDE
- Provide a solution to avoid making vulnerabilities, detect vulnerabilities at earlier phases of 
  development
- Quick Security Help with built-in Security Guidelines
- Real-time Vulnerability Notifications
- Static Analysis with Clang Static Analyser

##### HOW TO USE
_____________________________

- Quick Security Help with built-in Security Guidelines
 Activate it from the menu 'Security > Quick Security Help > Activate'.

- Real-time Vulnerability Notifications
 Activate it from the menu 'XSecurity > Vulnerability Notifications > Activate'.

- Static Analysis with Clang Static Analyser
 0. Jump to step 3. if you already done this when dealing with the checker  
 1. Quit Xcode.
 2. Run a script (checker/build/scripts/install.sh) to apply our clang to Xcode.
 3. Relaunch Xcode.
 4. Open your Xcode project.
 5. Scan the project with our checkers from the menu 'XSecurity > Static Security Analyzer > Analyze'.
    You many need to deep clean (Option+Command+Shift+K) the projecgt beforehand in some cases.


##### RELEASES
_____________________________

In XSecurity, as typical with other projects we use git tags to make our releases and aptly named as 
Release Tags. Usually one would download one of these Release Tags to build (and automatically 
apply XSecurity) and one may work on it. 


##### BRANCHES
_____________________________

This explains the branches and some conventions used in this project.

**master** branch:
  The release branch, where if something is merged here it indicates an upcoming release. 
  We take it as a convention that all merges to this branch is from develop branch. 
  Should you find a critical bug in one of these releases, please do report and use the latest 'master'
  branch instead.
                   
**develop** branch:
  Working features are merged in this branch, bug fixes of all sort too. If want to implement a feature,
  create a feature branch and do a pull request in order to merge that feature in this branch.

**feature** or **bug fix** branch:
  Develop features and bug fixes here, basically any branch made by the contributors. One convention we use
  in naming feature or bug fix branch is to have the branch name prefixed with "Feature_" and "BugFix_" 
  respective of their types.


##### BUG REPORTING
_____________________________

It is possible that Xcode may crash while XSecurity is loaded inside Xcode. It is our hope to deal with all 
those bugs, with your help we can facilitate it better. It will be very helpful if you could add to your bug 
reports the following information:

- Crash information (Xcode shows threads stack trace when it crashes. Please include them.)
- The operations you did before the crash (series of key strokes, mouse operations or combination of both)
- The source code snippet you were manipulating (a portion of code will not really mean to us, we promise not 
  to distribute it)
- Xcode version
- XSecurity version (Version number of the revision you built)

We would like to thank you in advance for this.

##### HOW DO WE HANDLE THE ISSUED BUGS
_____________________________

Reported bugs will be handled using the following steps.

- Confirm if the bug reproduce and the issue labeled as 'Bug'
- Fix the bug in 'develop' branch
- Reporter will confirm the fix
- Will label the issue with 'Done'
- Conduct regression test
- Merge the changes to 'master'
- Close the issue.

We greatly appreciate if you can do a pull request when fixing the bugs on your own.


##### LICENSE
_____________________________

XSecurity is available under 2 licenses.
- The Xcode plug-in is made available under the Apache 2.0 license.
- Clang and our custom security checkers for Clang Static Analyzer are available under the University of Illinois/NCSA Open Source License.

In line with this if you want to contribute in this project we encourage you to sign the Individual License Agreement (ICLA.TXT)

Should it contain code written by third parties, such software will have its own individual LICENSE.TXT file in the directory in which it appears. This file will describe the copyrights, license, and restrictions which apply to that code.

##### OTHER CONVENTIONS AND VALUES
_____________________________

As much as we value personal coding styles and personal conventions in creating code, as it reflects
our individuality and personality. We strongly adhere to our coding philosophies. One of it is we value 
clean coding and uniformity. We believe that clean code begets readability, modifiability and 
maintainability. This also applies to code uniformity thus it is with our great appreciation if you can 
blend in with our existing conventions.

- END
