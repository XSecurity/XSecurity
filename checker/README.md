### XSecurity (Checkers)

A security plugin in Xcode with clang analyzer's checkers for iOS application development. 
This plugin aims to reduce the vulnerability made during development by detecting the vulnerability 
as it is being created. 

This readme file is mainly for the Checkers for details about the plugin please see the readme file 
under the main folder.


##### PREPARATION
_____________________________

We included a clang binary with these checkers pre-built in it. If you want to just use the checkers right away after cloning this repository you can proceed to [INSTALLATION](#install). If you plan to contribute to this project or build it yourself, proceed on the following preparation **before cloning**.
We believe that it is better for you to build the original clang first. Then, include the checkers from this repository and build clang again. In this way you can tell whether your setup is working in the first place or not.


We plan to automate things for you but for the meantime please bear with us by following this procedure.

   
    Get the required tools.
      - See Getting Started with the LLVM System - Requirements.
      - Note that Python is needed for running the test suite. Get it at: http://www.python.org/download
   
    Checkout LLVM:
      - Change directory to where you want the llvm directory placed. This will be your [llvm working folder](#llvm_working_folder)
      - $ svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm 
        (Currently we are using the revision 200605. You should check it out with 
        -r option like svn co -r 200605 http://xxxx.)
   
    Checkout Clang:
      - cd llvm/tools
      - svn co http://llvm.org/svn/llvm-project/cfe/trunk clang 
        (Use same option mentioned above)
      - cd ../..
   
    Checkout extra Clang Tools: (optional)
      - cd llvm/tools/clang/tools
      - svn co http://llvm.org/svn/llvm-project/clang-tools-extra/trunk extra 
        (Use same option mentioned above)
      - cd ../../../..
   
    Checkout Compiler-RT:
      - cd llvm/projects
      - svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt 
        (Use same option mentioned above)
      - cd ../..
   
    Build LLVM and Clang:
      - mkdir build  
        (for building without polluting the source dir)
      - cd build
      - ../llvm/configure --enable-optimized --disable-compiler-version-checks

        (configure build folder which is outside the source dir)
        Note: At this point if you are able to successfully execute the above mentioned 
              command then you might want to have a coffee break or do something else 
              after executing the following make, since it will take a little while to complete.
      - make
   
    By now you may have the following folder structure:
      ____XSecurity                    <a name="repo_root" />(repo root folder)
       |____checker                    <a name="checker_folder" />(checker folder)
       | |____build
       | | |____Release+Asserts
       | | | |____bin
       | | |____scripts
       | |
       | |____llvm
       | | |____tools
       | | | |____clang
       | | | | |____lib
       | | | | | |____StaticAnalyzer
       | | | | | | |____Checkers
       | | | | |
       | | | | |____tools
       | | | | | |____scan-build
       | |  
       | |____test
       | 
       |____plugin
       | |____XSecurity
       | | |____XSecurity
   
   
      ____some_folder                   <a name="llvm_working_folder" />(llvm working folder)
       |____build
       | |____Release+Asserts
       | | |____bin
       | |____scripts
       |
       |____llvm
       | |____tools
       | | |____clang
       | | | |____lib
       | | | | |____StaticAnalyzer
       | | | | | |____Checkers
       | | | |
       | | | |____tools
       | | | | |____scan-build
   
    - At this point you have two choices if you already cloned the repository **1.) Move the repo files to llvm folder** or better when you are not able to clone the repository yet **2.) Overwrite checkers with repo files**  
    
###### 1.) Move the repo files to llvm folder
    NOTE:
    - Before moving the files, please take note of Checkers.td in llvm/tools/clang/lib/StaticAnalyzer/Checkers,
    be careful not to directly overwrite it, you may have the latest llvm source code and
    they may have addded more checkers compared to the checkers we have when we created our checkers.
    - It is highly advised that you compare the two versions of Checkers.td and add only the portion applicable to
      MSecIOSAppSec.
    - Move the the files under checker folder to the root folder of your [llvm working folder](#llvm_working_folder).
    
###### 2.) Overwrite checkers with repo files
    - Move to repo root folder  
      $ cd [repo root folder](#llvm_working_folder)/build
      TODO: Make this clear from the start

###### 3.) Rebuild clang 
    - Build clang again
      $ cd [llvm working folder](#llvm_working_folder)/build
      $ make

    - To confirm if the iOSAppSec checkers were built successfully execute the following under the same build folder.
      ./scripts/confirm_checker.sh iOS
   
      It will show you the list of the iOSAppSec checkers (there are 10 at the time of this writing)

  
##### <a name="install"/>INSTALLATION
_____________________________

You should do the following after succesfully building clang, under llvm working folder's build folder 
(the one with files in this repository) 
 - Quit Xcode if it is running.
 - execute [some_folder]/build/scripts/install.sh 


##### EXECUTION in Xcode
_____________________________

 Open Xcode and find "XSecurity" in the main menu, typically before the Help item.

 If you can't find the XSecurity menu then the plug-in was not loaded successfully. 
 Under "XSecurity", you can find the last menu item, "Static Security Analyzer". Under it select "Analyze". 


##### HOW TO UNINSTALL
_____________________________

Uninstall the plugin-in see the main readme file.


##### FEATURE LIST
_____________________________

These are the supported vulnerabilities.
- Insecure NSUserDefaults Usage
- Unencrypted Data in plist File
- Insecure Permanent Credential Storage
- Ignores Certificate Validation Errors
- Abusing URL Schemes
- Leaking Web Caches
- Leaking Logs
- Leaking Pasteboard
- SQL Injection (SQLite)
- Buffer Overflow APIs 


##### RELEASES, BRANCHES & BUG REPORTING
_____________________________

See the main readme file for these sections.


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

We greatly appreciate your pull request if you can make one.  


##### LICENSE
_____________________________

XSecurity is available under 2 licenses described as below.
The Xcode plug-in is made available under the Apache 2.0 license.
Clang and our custom security checkers for clang static analyzer
are available under the University of Illinois/NCSA Open Source License.

It contains code written by third parties. Such software will
have its own individual LICENSE.TXT file in the directory 
in which it appears. This file will describe the copyrights, 
license, and restrictions which apply to that code.



##### OTHER CONVENTIONS AND VALUES
_____________________________

As much as we value personal coding styles and personal conventions in creating code, as it reflects
our individuality and personality. We strongly adhere to our coding philosophies. One of it is we value 
clean coding and uniformity. We believe that clean code begets readablity, modifiability and 
maintainability. This also applies to code uniformity thus it is with our great appreciation if you can 
blend in with the following convetions.

