//===-- iOSAppSecLeakingWebCaches.cpp -----------------------------------------*- C++ -*--//
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
Under NSURLConnectionDataDelegate protocol

// 1st Instance
connection:openURL:sourceApplication:annotation:

// 2nd Instance
connection:handleWillCacheResponse:

*/
//
// Implementation Note:
//


// Sample Source code to detect:
/*

Bad Example:
 
 
//////////

(BOOL)connection:(UIApplication *)connection willCacheResponse:(NSURL *)url
{

}

*/

//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecLeakingWebCachesChecker

#include "ClangSACheckers.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

//#define MSEC_DBG
#include "clang/StaticAnalyzer/Core/MSecCommon.h"

using namespace clang ;
using namespace ento ;
using namespace msec_cmn ; 

namespace 
{
  //redwud: The main job of this class is to receive call backs for the points
  //        of interest for this checker.
  //        This will mostlikely have one instance. 
  class iOSAppSecLeakingWebCachesChecker 
    : public Checker< 
                     check::ASTDecl < ObjCImplementationDecl >  
                    > 
  {
 
  private:
    mutable IdentifierInfo 
                           *m_piiNSURLConnectionDataDelegate
                         , *m_piiConnection
                         , *m_piiWillCacheResponse ; 
    
    const StringRef       m_szReportDesc ;
    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;
    bool checkWillCacheResponse( const ObjCMethodDecl *pMD, ASTContext &Ctx ) const ;

  public:
    //redwud: Default Constructor
    iOSAppSecLeakingWebCachesChecker() ;

    // Smaller coverage/inner layer thus implementation declaration
    void checkASTDecl(const ObjCMethodDecl *pMD, AnalysisManager &rMgr, BugReporter &rBR) const ;

    // Bigger coverage/outler layer thus implementation declaration
    void checkASTDecl(const ObjCImplementationDecl *pImplDecl, AnalysisManager &rMgr, BugReporter &rBR) const ;

  } ; // end iOSAppSecLeakingWebCachesChecker  
}  // end anonymous namespace


//redwud: Default Constructor
iOSAppSecLeakingWebCachesChecker::iOSAppSecLeakingWebCachesChecker() 
  : m_piiNSURLConnectionDataDelegate(NULL)
  , m_piiConnection                 (NULL) 
  , m_piiWillCacheResponse          (NULL)  
  , m_szReportDesc                  ("Sensitive data is potentially cached in web caches.")
{
  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;
  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType( "Leaking Web Caches",
                                            "Side Channel Data Leakage" )) ;

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true ) ;

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
}

void iOSAppSecLeakingWebCachesChecker::checkASTDecl(const ObjCImplementationDecl *pImplDecl, AnalysisManager &rMgr, BugReporter &rBR) const 
{
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;

  ASTContext &Ctx = rBR.getContext() ;  

  do
  {
    initIdentifierInfo( Ctx ) ;

    const ObjCInterfaceDecl *pIfDecl = CMSecCommon::isSupportedProtocol( pImplDecl ->getClassInterface(), m_piiNSURLConnectionDataDelegate ) ;

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


void iOSAppSecLeakingWebCachesChecker::checkASTDecl(const ObjCMethodDecl *pMD, AnalysisManager &rMgr, BugReporter &rBR) const
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

    // connection:
    if ( S.getIdentifierInfoForSlot( 0 ) != m_piiConnection)
    {
      //MSEC_DEBUG("redwud: ","!connection: " << S.getAsString() ) ;
      break ;
    }

    ASTContext &Ctx = rBR.getContext() ; 

    // Two arguments
    if ( S.getNumArgs() != 2 )
    {
      break ;
    }
    
    // willCacheResponse:
    if ( S.getIdentifierInfoForSlot(1) != m_piiWillCacheResponse )
    {
      break ;
    }

    //Note: Intentionally made it common for both
    if ( !checkWillCacheResponse( pMD, Ctx ) )
    {
      break ;
    } 
    
    CMSecCommon::reportInsecureInstance( *m_pInsecureInstBugType
      , m_szReportDesc, rBR, pMD ) ; 
      
  } while(_PASSING_) ;

  MSEC_DEBUG_FUNC( "redwud: ", "EXIT (Method)" ) ;
}

//Note: FIXME: Needs reviewing
//      Determining whether there will be a vulnerable execution/behaviour is hard 
//      thus for the meantime warn the user that it returns YES, meaning it processed 
//      connection:openURL:sourceApplication:annotation: in Skype's case allowing
//      the phone to make a call without user's permission I guess.

//Temporary constraint: Only notifies one instance of non-zero return value, since 
//  this would be a lax checker so one is enough, the user will mostlikely get the idea anyway, 
//  maybe on the second time and so on. (Yeah rationalize it!)

//FIXME: There is something to fix here, I just forgot what it is all about  

bool iOSAppSecLeakingWebCachesChecker::checkWillCacheResponse( const ObjCMethodDecl *pMD, ASTContext &Ctx ) const
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
      
      //MSEC_DEBUG("redwud: ","Found return statement \n" ) ;
      //pReturnValue ->dumpColor() ;

      if ( pReturnValue ->isNullPointerConstant( Ctx, Expr::NPC_NeverValueDependent ) == Expr::NPCK_NotNull )
      {
        MSEC_DEBUG("redwud: ","Return non nil!!!  \n" ) ;
        bRet = true ;
      }

      if ( const IntegerLiteral *pIntLiteral = dyn_cast < IntegerLiteral > ( *(pReturnValue ->child_begin()) ) )
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

  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;

  return bRet ;
}

//NOTE: This method is made to be separated because ASTContext is not available during instatiation
void iOSAppSecLeakingWebCachesChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
  do
  {
    //redwud: prevent the following to from gettting reinitialized
    if ( m_piiConnection )
    {
      break ;      
    }

    MSEC_DEBUG_FUNC("redwud: ","ENTER") ;

    //Common ID
    m_piiNSURLConnectionDataDelegate = &Ctx.Idents.get("NSURLConnectionDataDelegate") ;
    m_piiConnection                  = &Ctx.Idents.get("connection") ;

    //1st Instance
    m_piiWillCacheResponse           = &Ctx.Idents.get("willCacheResponse") ;

    MSEC_DEBUG_FUNC("redwud: ","EXIT") ;

  } while (_PASSING_) ;
}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecLeakingWebCachesChecker(CheckerManager &rMgr) 
{
  rMgr.registerChecker< iOSAppSecLeakingWebCachesChecker >();
}

