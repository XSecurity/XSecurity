### XSecurity

A security plugin in Xcode with clang analyzer's checkers for iOS application development. 
This plugin aims to reduce the vulnerability made during development by detecting the vulnerability 
as it is being created. You can also follow us on twitter: https://twitter.com/prj_xsecurity for 
more updates regarding this tool.

This readme file is mainly for the plugin itself for details about the checkers please see
the readme file under checker folder.

Support Xcode Versions
Xcode 5.0.2

##### INSTALLATION
_____________________________

Download source code(See also "BRANCHES/RELEASES" section) and open XSecurity.xcodeproj on Xcode.

If your Xcode's version is not 4.6, 5.0.2 and 5.1 then you need to add the new DVTPlugInCompatibilityUUID
to XSecurity Xcode Project. In order to do that please do the following things.

1.) Retrieve DVTPlugInCompatibilityUUID
- On a Terminal window execute the following command to get DVTPlugInCompatibilityUUID of Xcode.
$ defaults read /Applications/Xcode.app/Contents/Info DVTPlugInCompatibilityUUID

- NOTE: Some version 5 Xcode is using /Applications/Xcode5.app/ 
  You may want to use the specific version of Xcode applicable to your current environment
- Take note of the displayed UUID


2.) Add DVTPlugInCompatibilityUUID to the Xcode project
- In the previously created project (bundle) show Project Navigator
- Select the project, and on TARGETS select the default target and choose Info
- If DVTPlugInCompatibilityUUIDs Key is not present add it and select Array for the Type
- Add new item under DVTPlugInCompatibilityUUIDs and put the UUID retrieved in the previous section.

Screen Shot:
![alt text](https://github.com/XSecurity/XSecurity/tree/master/plugin/XSecurity/DVTPlugInCompatibilityUUID.png "Adding DVTPlugInCompatibilityUUID")

Additionally if you are using Xcode 5.1 and later you need to comment out [GCC_ENABLE_OBJC_GC = supported;] 
because it is no longer supported in this version and onwards. After doing that when you build, there
will be a lot of warnings. Please ignore those warnings, at the time of this writing we are working to remove 
these warnings.


Continue the instalation:

In Xcode select the appropriate Scheme. 
Go to "Edit Scheme" and set instances of "Build Configuration" to "Release"  
Execute build and it will automatically install the plugin into the correct directory.
Quit Xcode and start it again. (Make it sure that Xcode proccess is fully terminate)
This time XSecurity will be loaded, you will mostlikely find a menu item: XSecurity in the main menu. 

##### HOW TO UNINSTALL
_____________________________

Delete the following directory:
$HOME/Library/Application\ Support/Developer/Shared/Xcode/Plug-ins/XSecurity.xcplugin


##### FEATURE LIST
_____________________________

- Centralize developer-friendly security features on Xcode IDE
- Provide a solution to avoid making vulnerabilities, detect vulnerabilities at earlier phases of 
  development
- Quick Security Help with built-in Security Guidelines
- Real-time Vulnerability Notifications
- Static Analysis with Clang Static Analyzer


##### RELEASES
_____________________________

In XSecurity, as typical with other projects we use git tags to make our releases and aptly named as 
Realeaes Tags. Typically one would download one of these Release Tags to build (and automatically 
apply XSecurity) and work on it. 


##### BRANCHES
_____________________________

This explains the branches and some conventions used in this project.

master branch:
  The release branch, where if something is merged here it indicates an upcoming release. 
  We take it as a convention that all merges to this branch is from develop branch. 
  Should you find a critical bug in one of these releases, please do report and use the latest 'master'
  branch instead.
                   
develop branch:
  Working features are merged in this branch, bug fixes of all sort too. If want to implement a feature,
  create a feature branch and do a pull request in order to merge that feature in this branch.

feature or bug fix branch:
  Develop features and bug fixes here, basically any branch made by the contributors. One convention we use
  in naming feaure or bug fix branch is to have the branch name prefixed with "Feature_" and "BugFix_" 
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

We greatly appreciate your pull request if you can make one.  See some section (TBD) for more details. 


##### LICENSE
_____________________________

XSecurity is available under 2 licenses described as below.
The Xcode plug-in is made available under the Apache 2.0 license. In line with this if you want to contribute 
in this project we encourage you to sign the Individual License Agreement (ICLA.TXT)

Clang and the custom security checkers for clang static analyzer are available under the University of 
Illinois/NCSA Open Source License.

It contains code written by third parties. Such software will have its own individual LICENSE.TXT file in the
directory in which it appears. This file will describe the copyrights, license, and restrictions which apply 
to that code.


##### OTHER CONVENTIONS AND VALUES
_____________________________

As much as we value personal coding styles and personal conventions in creating code, as it reflects
our individuality and personality. We strongly adhere to our coding philosophies. One of it is we value 
clean coding and uniformity. We believe that clean code begets readablity, modifiability and 
maintainability. This also applies to code uniformity thus it is with our great appreciation if you can 
blend in with the following convetions.

