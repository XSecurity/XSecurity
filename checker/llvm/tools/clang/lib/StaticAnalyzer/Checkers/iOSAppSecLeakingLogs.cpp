//===-- iOSAppSecLeakingLogsChecker.cpp -----------------------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/*

NSLog(@"Authentication Token: %@", token);

*/

//
// Implementation Note:
//
// NSLogv should be supported however, the variadic parameter is unbearable as of 
// the creation of this checker, thus being postponed.
//
//
//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecLeakingLogsChecker

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#define MSEC_DBG
#include "clang/StaticAnalyzer/Core/MSecCommon.h"
#include "SensitiveInfo.h"

using namespace clang ;
using namespace ento ;
using namespace msec_cmn ; 

namespace 
{
  //redwud: The main job of this class is to receive call backs for the point
  //        of interests for this checker.
  //        This will mostlikely have one instance. 
  class iOSAppSecLeakingLogsChecker 
    : public Checker< 
                      check::PostCall
                    > 
  {
 
  protected:
    mutable IdentifierInfo  *m_piiNSLog
                          , *m_piiNSLogv ;

    const StringRef       m_szReportDesc ;    
    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;

  public:
    //redwud: Default Constructor
    iOSAppSecLeakingLogsChecker() ;
  
    /// Process SecItemAdd() and SecItemUpdate().
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  };
  
} // end anonymous namespace
  

//redwud: Default Constructor
iOSAppSecLeakingLogsChecker::iOSAppSecLeakingLogsChecker() 
  : m_piiNSLog    (NULL)
  , m_piiNSLogv   (NULL)
  , m_szReportDesc("Sensitive information is leaked via Logs.")  
{
//  MSEC_DEBUG_FUNC("redwud:","ENTER") ;
  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType( "Leaking Logs",
                                            "Side Channel Data Leakage" ));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true );

//  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
}


/// Process NSLog() and NSLogV().

//Interfaces:
//void NSLog (
//       NSString *format,
//          ...
//    );

//void NSLogv (
//       NSString *format,
//          va_list args
//    );
//#define MSEC_DBG

void iOSAppSecLeakingLogsChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const 
{
  do
  {
    if ( !m_pInsecureInstBugType )
    {
      // MSEC_DEBUG( "redwud: ", "!m_pInsecureInstBugType" ) ;
      break ;
    }

    initIdentifierInfo( C.getASTContext() ) ;

    //redwud: Obviously it is what it is
    if ( !Call.isGlobalCFunction() )
    {
      // MSEC_DEBUG( "redwud: ", "!Call.isGlobalCFunction" ) ;
      break ;
    }

    const IdentifierInfo *pCalleeIdent = Call.getCalleeIdentifier() ; 

    unsigned iNumArgs = Call.getNumArgs() ; 

    //We do away with array because it's only two of them and it
    //will break the while..passing pattern  
    if ( pCalleeIdent != m_piiNSLog )
    {  
      if ( (pCalleeIdent != m_piiNSLogv) )
      {
        break ;
      }
      // This path is for NSLogv(), don't get confused!!!

      //FIXME: Workaround to evade 2nd and onward parameters of NSLogv
      //  Idea: Use identifier for slot... ??? whoops I did it again!
      iNumArgs = 1 ;
    }

    CSensitiveInfo &rSenInfo = CSensitiveInfo::create() ;
    SymbolRef pSymToCheck = NULL ; 
   
    // Go through each parameter unless find some sensitive info in one of them
    for ( unsigned iCtr = 0; (iCtr < iNumArgs) && (!pSymToCheck); iCtr++ )
    {
      const Expr *pExpr = Call.getArgExpr( iCtr ) ;
      StringRef szString ;
      StringRef szVarName ;

      CMSecCommon::getStrFromExpr( szString, pExpr, &szVarName ) ; 

      if ( szString.empty() ) // Nil is supported here, so no need to check
      {
//        MSEC_DEBUG( "redwud: ", "Empty string" ) ;
        continue ;
      }

      if ( !rSenInfo.isSensitive( szString.str() ) && !rSenInfo.isSensitive( szVarName.str() ) )
      {
//        MSEC_DEBUG( "redwud: ", "!Sensitive :" << szString << "Var name: " << szVarName ) ;
        continue ; 
      }

      // Get the symbolic value corresponding to the target parameter.
      pSymToCheck = Call.getArgSVal( iCtr ).getAsSymbol() ;
     
      //Force the issue
      if ( !pSymToCheck )
      {
        pSymToCheck = CMSecCommon::conjureSymbolRef() ;
      }
    }

    if ( !pSymToCheck )
    {
      break ;
    }

    ProgramStateRef pProgState = C.getState() ; 

    //Report this instance
    CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
      , *m_pInsecureInstBugType, m_szReportDesc ) ;
  
  } while ( _PASSING_ ) ;

}

//#undef MSEC_DBG

//NOTE: This method is made to be separated because ASTContext is not available during instatiation
void iOSAppSecLeakingLogsChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
 
  do
  {
    //redwud: prevent the following to from gettting reinitialized
    if ( m_piiNSLog )
    {
      break ;      
    }

    MSEC_DEBUG_FUNC("redwud:","ENTER") ;

    m_piiNSLog  = &Ctx.Idents.get("NSLog") ;
    m_piiNSLogv = &Ctx.Idents.get("NSLogv") ;

    MSEC_DEBUG_FUNC("redwud:","EXIT") ;

  } while (_PASSING_) ;
}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecLeakingLogsChecker(CheckerManager &rMrg) 
{
  rMrg.registerChecker<iOSAppSecLeakingLogsChecker>();
}

