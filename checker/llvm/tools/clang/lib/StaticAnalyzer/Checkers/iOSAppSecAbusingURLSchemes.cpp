//===-- iOSAppSecIgnoresValidationErrors.cpp -----------------------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// The checker should be able to detect the following sample code,

/*
Under UIApplicationDelegate protocol

// 1st Instance
application:openURL:sourceApplication:annotation:

// 2nd Instance
application:handleOpenURL:

*/
//
// Implementation Note:
//


// Sample Source code to detect:
/*

Bad Example:
 
In your Application Delegate
 
- (BOOL)application:(UIApplication *)application
openURL:(NSURL *)url
sourceApplication:(NSString *)sourceApplication
annotation:(id)annotation {
 
// Perform transaction like Skype which allowed a malicious call
 
return YES;
}

//////////

(BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url
{
  // Ask for authorization
  // Perform transaction
}

*/

//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecAbusingURLSchemesChecker

#include "ClangSACheckers.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#define MSEC_DBG
#include "clang/StaticAnalyzer/Core/MSecCommon.h"

using namespace clang ;
using namespace ento ;
using namespace msec_cmn ; 

namespace 
{
  //redwud: The main job of this class is to receive call backs for the points
  //        of interest for this checker.
  //        This will mostlikely have one instance. 
  class iOSAppSecAbusingURLSchemesChecker 
    : public Checker< 
                     check::ASTDecl < ObjCImplementationDecl >  
                    > 
  {
 
  private:
    mutable IdentifierInfo 
                           *m_piiUIApplicationDelegate
                         , *m_piiApplication
                         , *m_piiOpenURL          
                         , *m_piiSourceApplication
                         , *m_piiAnnotation       
                         , *m_piiHandleOpenURL     ; 
    
    const StringRef       m_szReportDesc ;
    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;
    bool checkOpenURL( const ObjCMethodDecl *pMD, ASTContext &Ctx ) const ;

  public:
    //redwud: Default Constructor
    iOSAppSecAbusingURLSchemesChecker() ;

    void checkASTDecl(const ObjCMethodDecl *pMD, AnalysisManager &rMgr, BugReporter &rBR) const ;

    void checkASTDecl(const ObjCImplementationDecl *pImplDecl, AnalysisManager &rMgr, BugReporter &rBR) const ;

  } ; // end iOSAppSecAbusingURLSchemesChecker  
}  // end anonymous namespace


//redwud: Default Constructor
iOSAppSecAbusingURLSchemesChecker::iOSAppSecAbusingURLSchemesChecker() 
  : m_piiUIApplicationDelegate(NULL)
  , m_piiApplication          (NULL) 
  , m_piiOpenURL              (NULL)  
  , m_piiSourceApplication    (NULL)  
  , m_piiAnnotation           (NULL)  
  , m_piiHandleOpenURL        (NULL)   
  , m_szReportDesc            ("Malicious activities be performed due to insecure implementation of URL Schemes.") 
{
  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;
  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType( "Abusing URL Schemes",
                                            "Security Decisions Via Untrusted Inputs" ));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true ) ;

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
}


void iOSAppSecAbusingURLSchemesChecker::checkASTDecl(const ObjCImplementationDecl *pImplDecl, AnalysisManager &rMgr, BugReporter &rBR) const 
{
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;

  ASTContext &Ctx = rBR.getContext() ;  

  do
  {
    initIdentifierInfo( Ctx ) ;

    const ObjCInterfaceDecl *pIfDecl = CMSecCommon::isSupportedProtocol( pImplDecl ->getClassInterface(), m_piiUIApplicationDelegate ) ;

    if ( !pIfDecl )
    { 
      MSEC_DEBUG( "redwud: ", "!pIfDecl" ) ;
      break ;
    }

    //Pitfall: This should be instance method
    for ( ObjCImplementationDecl::instmeth_iterator pItem = pImplDecl ->instmeth_begin()
            , pEndItem = pImplDecl ->instmeth_end(); 
          pItem != pEndItem;
          ++pItem )
    {
      checkASTDecl( (*pItem), rMgr, rBR ) ; 
    } 
  } while (_PASSING_) ;

  MSEC_DEBUG_FUNC( "redwud: ", "EXIT" ) ;
}


void iOSAppSecAbusingURLSchemesChecker::checkASTDecl(const ObjCMethodDecl *pMD, AnalysisManager &rMgr, BugReporter &rBR) const
{
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER (Method)" ) ;

  do
  {
    if ( !pMD )
    {
      break ;
    }
    
    Selector S = pMD ->getSelector() ;

    //There is no point of checking if you can't report it   
    if ( !m_pInsecureInstBugType )
    {
      MSEC_DEBUG("redwud: ","Reporting will fail!" ) ;
      break ;
    }

    // application:
    if ( S.getIdentifierInfoForSlot( 0 ) != m_piiApplication )
    {
      //MSEC_DEBUG("redwud: ","!application: " << S.getAsString() ) ;
      break ;
    }

    unsigned iArgs = S.getNumArgs() ;
    ASTContext &Ctx = rBR.getContext() ; 

    //
    //openURL:
    //

    do
    {
      if ( iArgs != 4 )
      {
        break ;
      }
      
      if ( (S.getIdentifierInfoForSlot(1) != m_piiOpenURL) 
           || (S.getIdentifierInfoForSlot(2) != m_piiSourceApplication)
           || (S.getIdentifierInfoForSlot(3) != m_piiAnnotation ) )
      {
        break ;
      }
          
      if ( !checkOpenURL( pMD, Ctx ) )
      {
        break ;
      } 
      
      CMSecCommon::reportInsecureInstance( *m_pInsecureInstBugType
        , m_szReportDesc 
        , rBR, pMD ) ; 
    
    } while(_PASSING_) ;

    //
    //handleOpenURL:
    //

    do
    {
      if ( iArgs != 2 )
      {
        break ;
      }
      
      if ( S.getIdentifierInfoForSlot(1) != m_piiHandleOpenURL )
      {
        break ;
      }
      
      //Note: Intentionally made it common for both
      if ( !checkOpenURL( pMD, Ctx ) )
      {
        break ;
      } 
      
      CMSecCommon::reportInsecureInstance( *m_pInsecureInstBugType
        , m_szReportDesc, rBR, pMD ) ;
    
    } while(_PASSING_) ; //handleOpenURL:
  
  } while(_PASSING_) ;

  MSEC_DEBUG_FUNC( "redwud: ", "EXIT (Method)" ) ;
}

//Note: Determining whether there will be a vulnerable execution/behaviour is hard 
//      thus for the meantime warn the user that it returns YES, meaning it processed 
//      application:openURL:sourceApplication:annotation: in Skype's case allowing
//      the phone to make a call without user's permission I guess.

//Temporary constraint: Only notifies one instance of non-zero return value, since 
//  this would be a lax checker so one is enough, user will mostlikely get it anyway, 
//  maybe on the second time and so on. (Yeah rationalize it!)

//Limitation: Can only detect if the return value is a literal boolean or numeric value.
//            If it is using a variable or a return value from a other function or message 
//            it can't detect the actual value.
bool iOSAppSecAbusingURLSchemesChecker::checkOpenURL( const ObjCMethodDecl *pMD, ASTContext &Ctx ) const
{
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;
  bool bRet = false ;


  do
  {
    if ( !pMD )
    {
      break ;
    }

    Stmt *pStBody = pMD ->getBody() ;
    
    if ( !pStBody )
    {
      MSEC_DEBUG("redwud: ","Impossible to have nobody!" ) ;
      break ;
    }
      
    MSEC_DEBUG("redwud: ","Iterating each child" ) ;
    
    for ( Stmt::child_iterator pItem = pStBody ->child_begin()
            , pEndItem = pStBody ->child_end() ;
          (pItem != pEndItem) && (!bRet) ;
          pItem++ )
    {
      if ( pItem ->getStmtClass() != Stmt::ReturnStmtClass )
      {
        continue ;
      }
   
      ReturnStmt *pRetStmt = cast < ReturnStmt > (*pItem) ; 
      Expr *pReturnValue = pRetStmt ->getRetValue() ; 

      if ( !pReturnValue )
      {
        break ;
      }
       
      MSEC_DEBUG("redwud: ","Found return statement " ) ;
      //pReturnValue ->dumpColor() ;

      pReturnValue ->dump() ;

      if ( const ObjCBoolLiteralExpr *pBool = dyn_cast < ObjCBoolLiteralExpr > ( pReturnValue ) )
      {
        if ( pBool ->getValue() )
        {
          bRet = true ;
          break ;
        }
      }
    
      Expr::child_iterator piChild = pReturnValue ->child_begin() ;

      if ( pReturnValue ->child_end() == piChild )
      {
        MSEC_DEBUG( "redwud: ", "last child !!!\n" ) ;
        break ;
      }


      if ( const IntegerLiteral *pIntLiteral = dyn_cast < IntegerLiteral > ( *piChild ) )
      {
        MSEC_DEBUG("redwud: ","Return Value " << (pIntLiteral)  ) ;

        if ( pIntLiteral ->getValue().getBoolValue() )
        {
          bRet = true ;
          break ;
        }
      }
    } // Each statement in the body
  } while(_PASSING_) ;

  MSEC_DEBUG_FUNC( "redwud: ", "EXIT" ) ;

  return bRet ;
}


//NOTE: This method is made to be separated because ASTContext is not available during instatiation
void iOSAppSecAbusingURLSchemesChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
  do
  {
    //redwud: prevent the following to from gettting reinitialized
    if ( m_piiApplication )
    {
      break ;      
    }

    MSEC_DEBUG_FUNC("redwud: ","ENTER") ;

    //Common ID
    m_piiUIApplicationDelegate = &Ctx.Idents.get("UIApplicationDelegate") ;
    m_piiApplication           = &Ctx.Idents.get("application") ;

    //1st Instance
    m_piiOpenURL               = &Ctx.Idents.get("openURL") ;
    m_piiSourceApplication     = &Ctx.Idents.get("sourceApplication") ;
    m_piiAnnotation            = &Ctx.Idents.get("annotation") ;   

    //2nd Instance
    m_piiHandleOpenURL         = &Ctx.Idents.get("handleOpenURL") ;

    MSEC_DEBUG_FUNC("redwud: ","EXIT") ;

  } while (_PASSING_) ;
}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecAbusingURLSchemesChecker(CheckerManager &rMgr) 
{
  rMgr.registerChecker< iOSAppSecAbusingURLSchemesChecker >();
}

