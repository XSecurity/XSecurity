### Building Clang with XSecurity Checkers

For your working environment readily available to contribute to XSecurity,carry on with this guide. 

##### PREPARATION
_____________________________

We believe that it is better for you to build the original Clang first. Then, include the checkers from this repository and build Clang again. In this way you can tell whether your setup is working in the first place or not.
We plan to automate things for you but for the meantime please bear with us by following this procedure.


######Get The Required Tools.

- See [Getting Started with the LLVM System - Requirements.](http://llvm.org/docs/GettingStarted.html#requirements)
- Note that Python is needed for running the test suite. You can get it [here:](http://www.python.org/download)

######Checkout LLVM:

- Create your repo root folder, e.g. "XSecurity". Later it will be explained later why this is your repo folder.
- Under it create another folder and should be named "checker"
- Change to this checker folder. This will be your [llvm working folder](#llvm_working_folder)
- We''ve been using the revision 200605, thus the use of -r option.

Accordingly can be done by doing...

    $ mkdir XSecurity 
    $ cd XSecurity
    $ mkdir checker 
    $ cd checker 
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

By now you may have a similar folder structure as the following: (<a name="repo_root_folder" />repo root folder -> "XSecurity" below, <a name="llvm_working_folder" />llvm working folder -> "checker" below)


    __XSecurity               <- repo root folder
    |____checker              <- llvm working folder
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


######Overwrite the llvm working folder with Repo Files
Instead of cloning this repository you should fetch the repository from your [repo root folder](#repo_root_folder). If either fetch or checkout fails just add -f for the option and will be good to go.  

    $ cd <repo root folder: XSecurity> 
    $ git init 
    $ git remote add origin https://github.com/XSecurity/XSecurity.git 
    $ git fetch origin 
    $ git checkout --track origin/master 

The resulting folder structure should look like the following:

    __XSecurity               <- repo root folder
    |____checker              <- llvm working folder
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
    

######Rebuild Clang 

Build Clang again in [llvm working folder](#llvm_working_folder)/build

    $ cd <llvm working folder: checker>/build
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

