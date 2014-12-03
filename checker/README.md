### XSecurity (Checkers)
A security plug-in in Xcode with Clang analyzer's checkers for iOS application development. This readme is purely related to Checkers, for details about the plug-in please see the [README](https://github.com/XSecurity/XSecurity) file under the main folder.


##### PREPARATION
_____________________________

We included a Clang binary with these checkers pre-built in it. If you want to just use the checkers right away, clone this repository and proceed to [INSTALLATION](#install). 

**NOTE: Before cloning this repository!**

- *If you plan to* **contribute** *to this project we highly suggest that you follow [this guide](https://github.com/XSecurity/XSecurity/blob/master/BUILD_CLANG_AND_HELP.md) instead.* 
- *If you* **just want to build** *it yourself and don't want reflect your changes,* **carry on!.**

We believe that it is better for you to build the original Clang first. Then, include the checkers from this repository and build Clang again. In this way you can tell whether your setup is working in the first place or not.
We plan to automate things for you but for the meantime please bear with us by following this procedure.


######Get The Required Tools.

- See [Getting Started with the LLVM System - Requirements.](http://llvm.org/docs/GettingStarted.html#requirements)
- Note that Python is needed for running the test suite. You can get it [here:](http://www.python.org/download)

######Checkout LLVM:

- Change directory to where you want the llvm directory placed. This will be your [llvm working folder](#llvm_working_folder)
- We've been using the revision 200605, thus the use of -r option.

Accordingly can be done by doing...

    $ cd < llvm working folder > 
    $ svn co -r 200605 http://llvm.org/svn/llvm-project/llvm/trunk llvm 


######Checkout Clang:

    $ cd ./llvm/tools
    $ svn co -r 200605 http://llvm.org/svn/llvm-project/cfe/trunk clang 

Checkout extra Clang Tools: (optional)

    $ cd ../../llvm/tools/clang/tools
    $ svn co -r 200605 http://llvm.org/svn/llvm-project/clang-tools-extra/trunk extra 

Checkout Compiler-RT:

    $ cd ../../../../llvm/projects
    $ svn co -r 200605 http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt 

######Build LLVM and Clang: 

To build without polluting the source directory

    $ cd ../..
    $ mkdir build  
    $ cd build

**Note:** The following may take little while. This is to configure the build folder which is outside the source directory.

    $ ../llvm/configure --enable-optimized --disable-compiler-version-checks

**Note:** At this point if you are able to successfully execute the above mentioned command after executing the following make command, then you might want to have a coffee break or do something else since it will take time to complete.

    $ make

By now you may have a similar folder structure as the following: <a name="llvm_working_folder" />(llvm working folder -> "some_folder" below)
        
    ___some_folder             <- llvm working folder 
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

######Clone the Repository

    $ git clone https://github.com/XSecurity/XSecurity.git ./XSecurity

<a name="repo_root" />(repo root folder -> "XSecurity" below, <a name="checker_folder" />checker folder -> "checker" below)

    __XSecurity               <- repo root folder
    |____checker              <- checker folder
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
    |____plug-in
    | |____XSecurity
    | | |____XSecurity
    

######Overwrite the llvm working folder with Repo Files

**NOTE:  If you are using the most recent version of Clang and need to use the recent Checkers**

- Before overwriting the files, please take note of Checkers.td and CMakeLists.txt in llvm/tools/clang/lib/StaticAnalyzer/Checkers of [llvm working folder](#llvm_working_folder). We suggest that you do not overwrite it right away, if you have the latest llvm source code and the authors may have addded more checkers compared to the checkers we have when we created our checkers.
- It is highly advised that you compare the two versions of the said files and add only the portion applicable to MSecIOSAppSec.

Copy the contents of [checker folder](#checker_folder) to your [llvm working folder](#llvm_working_folder).

    $ cp -ir < checker folder >/* < llvm working folder >/*  


######Rebuild Clang 

Build Clang again in [llvm working folder](#llvm_working_folder)/build

    $ cd < llvm working folder >/build
    $ make

To confirm if the iOSAppSec checkers were built successfully execute the following under the same build folder.
It will show you the list of the iOSAppSec checkers (there are 11 checkers at the time of this writing)

    $ ./scripts/confirm_checker.sh iOSAppSec


##### <a name="install"/>INSTALLATION
_____________________________

You should do the following after succesfully building Clang, under [llvm working folder](#llvm_working_folder)'s build folder 
(the one with files in this repository) 
- Quit Xcode if it is running.
- Execute [llvm working folder](#llvm_working_folder)/build/scripts/install.sh 


##### RUNNING the CHECKERS in Xcode
_____________________________

Open Xcode and find "XSecurity" in the main menu, typically before the Help item. If you can't find the XSecurity menu then the plug-in was not loaded/installed successfully. Under "XSecurity", you can find the last menu item, "Static Security Analyzer". Under it select "Analyze". 


##### UNINSTALL
_____________________________

- Quit Xcode if it is running.
- Execute [llvm working folder](#llvm_working_folder)/build/scripts/restore_old_clang.sh 


##### FEATURE LIST
_____________________________

These are the supported weakness/vulnerabilities.
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


##### RELEASES, BRANCHES, BUG REPORTING & HOW DO WE HANDLE THE ISSUED BUGS
_____________________________

See the main [README](https://github.com/XSecurity/XSecurity#releases) file for these topics.


##### LICENSE
_____________________________

XSecurity is available under 2 licenses.
- The Xcode plug-in is made available under the Apache 2.0 license.
- Clang and our custom security checkers for Clang Static Analyzer are available under the University of Illinois/NCSA Open Source License.

In line with this if you want to contribute in this project we encourage you to sign the Individual License Agreement (ICLA.TXT)

Should it contain code written by third parties, such software will have its own individual LICENSE.TXT file in the directory in which it appears. This file will describe the copyrights, license, and restrictions which apply to that code.


##### OTHER CONVENTIONS AND VALUES
_____________________________

As much as we value personal coding styles and conventions in creating code, as it reflects
our individuality and personality. We strongly adhere to our coding philosophies. One of it is we value 
clean coding and uniformity. We believe that clean code begets readablity, modifiability and 
maintainability. This also applies to code uniformity thus it is with our great appreciation if you can 
blend in with our existing convetions.

