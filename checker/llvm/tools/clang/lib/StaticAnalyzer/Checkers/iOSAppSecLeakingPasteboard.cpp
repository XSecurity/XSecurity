//===-- iOSAppSecLeakingPasteboard.cpp -----------------------------------------*- C++ -*--//
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
connection:openURL:sourceApplication:annotation:

// 2nd Instance
connection:handleUIPasteboard:

*/
//
// Implementation Note:
//


// Sample Source code to detect:
/*

Bad Example:
 
In your Application Delegate
 
- (BOOL)connection:(UIApplication *)connection
openURL:(NSURL *)url
sourceApplication:(NSString *)sourceApplication
annotation:(id)annotation {
 
// Perform transaction like Skype which allowed a malicious call
 
return YES;
}

//////////

(BOOL)connection:(UIApplication *)connection handleUIPasteboard:(NSURL *)url
{
  // Ask for authorization
  // Perform transaction
}

*/

//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecLeakingPasteboardChecker

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
  class iOSAppSecLeakingPasteboardChecker 
    : public Checker< 
                      check::PostObjCMessage
                    > 
  {
 
  private:
    mutable IdentifierInfo
                           *m_piiUIPasteboard
                         , *m_piiSetData
                         , *m_piiForPasteboardType
                         , *m_piiSetValue
                         , *m_piiAddItems
                         ; 

    const StringRef         m_szReportDesc ;
    mutable IdPtrVectorType m_vPropertyIdPtrs ;
    OwningPtr < BugType >   m_pInsecureInstBugType ;
 
    void initIdentifierInfo(ASTContext &Ctx) const;
    bool checkWillCacheResponse( const ObjCMethodDecl *pMD, ASTContext &Ctx ) const ;
    SymbolRef checkAddItems( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const ;
    SymbolRef checkProperties( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const ;

  public:
    //redwud: Default Constructor
    iOSAppSecLeakingPasteboardChecker() ;

    void checkPostObjCMessage( const ObjCMethodCall &M, CheckerContext &C ) const ;
    SymbolRef checkSetDataValueInstance( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx
        , IdentifierInfo *pDataValue, IdentifierInfo *pPBType ) const ;

  } ; // end iOSAppSecLeakingPasteboardChecker  
}  // end anonymous namespace


//redwud: Default Constructor
iOSAppSecLeakingPasteboardChecker::iOSAppSecLeakingPasteboardChecker() 
  : m_piiUIPasteboard     (NULL)
  , m_piiSetData          (NULL) 
  , m_piiForPasteboardType(NULL) 
  , m_piiSetValue         (NULL)
  , m_piiAddItems         (NULL)  
  , m_szReportDesc        ("Sensitive information might be leaked via the pasteboard.") 
{
  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;
  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType( "Leaking Pasteboard",
                                            m_szReportDesc ));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true ) ;

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
}

void iOSAppSecLeakingPasteboardChecker::checkPostObjCMessage( const ObjCMethodCall &M, CheckerContext &C ) const
{
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;
  SymbolRef pSymToCheck = NULL ;

  do
  {
    if ( !m_pInsecureInstBugType )
    {
      MSEC_DEBUG("redwud:","!m_pInsecureInstBugType") ;
      break ;
    }

    ASTContext &Ctx = C.getASTContext() ;  
    ProgramStateRef pProgState = C.getState() ;
    
    initIdentifierInfo( Ctx ) ;

    //Check receiver interface (FIXED: It applies to properties)
    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      MSEC_DEBUG( "redwud: ", "!pRxInterface" ) ;
      break ;
    }
    
    //UIPasteboard 
    if ( pRxInterface ->getIdentifier() != m_piiUIPasteboard )
    {
      //MSEC_DEBUG( "redwud: ", "!Rx RxIdentifier != UIPasteboard" ) ;

      //IdentifierInfo *pInfo = pRxInterface ->getIdentifier() ;

      //if ( !pInfo )
      //{
      //  break ;
      //}

      //MSEC_DEBUG( "redwud: ", "name: " << pInfo ->getName() ) ;
      break ;
    }
      
    pSymToCheck = checkSetDataValueInstance( M, C, Ctx, m_piiSetData, m_piiForPasteboardType ) ;
    
    if ( pSymToCheck  )
    {
      //Report this instance
      CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
              , *m_pInsecureInstBugType, m_szReportDesc ) ;
    }

    pSymToCheck = checkSetDataValueInstance( M, C, Ctx, m_piiSetValue, m_piiForPasteboardType ) ;
    
    if ( pSymToCheck )
    {
      //Report this instance too!
      CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
              , *m_pInsecureInstBugType, m_szReportDesc ) ;
    }

    pSymToCheck = checkAddItems( M, C, Ctx ) ;
    
    if ( pSymToCheck )
    {
      //Report this instance too!
      CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
              , *m_pInsecureInstBugType, m_szReportDesc ) ;
    }

    pSymToCheck = checkProperties( M, C, Ctx ) ;
   
    if ( pSymToCheck )
    {
      //Report this instance too!
      CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
              , *m_pInsecureInstBugType, m_szReportDesc ) ;
    }

  } while (_PASSING_) ;

  MSEC_DEBUG_FUNC( "redwud: ", "EXIT" ) ;
}

SymbolRef iOSAppSecLeakingPasteboardChecker::checkSetDataValueInstance( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx
    , IdentifierInfo *pDataValue, IdentifierInfo *pPBType ) const
{
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;
  SymbolRef pRet = NULL ;

  do
  {
    Selector selCurr = M.getSelector() ;

    //setData:forPasteboardType:
    if ( selCurr.getNumArgs() != 2 )
    {
      // Unlikely to be of concerned
      break ;
    }
    
    //setData:
    if ( selCurr.getIdentifierInfoForSlot(0) != pDataValue )
    {
      break ;
    }

    //forPasteboardType: 
    if ( selCurr.getIdentifierInfoForSlot(1) != pPBType )
    {
      break ;
    }
    
    ProgramStateRef pProgState = C.getState() ;
    const LocationContext *pLCtx = C.getLocationContext() ;
   
    //Check the value for "data" parameter (1st)
    SVal argVal = pProgState ->getSVal( M.getArgExpr(0), pLCtx ) ;

    if ( argVal.isUnknownOrUndef() || argVal.isZeroConstant() )
    {
      break ; 
    }

    //Check the value for "pasteboardType" parameter (2nd)
    argVal = pProgState ->getSVal( M.getArgExpr(1), pLCtx ) ;

    if ( argVal.isUnknownOrUndef() || argVal.isZeroConstant() )
    {
      break ; 
    }
 
    //Get receiver as symbol
    SymbolRef pSymInstance = M.getReceiverSVal().getAsSymbol() ;

    if ( !pSymInstance )
    {
      break ; 
    }

    pRet = pSymInstance ; 
  
  } while (_PASSING_) ;
  
  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;

  return pRet ;
}

SymbolRef iOSAppSecLeakingPasteboardChecker::checkAddItems( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const
{
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;
  SymbolRef pRet = NULL ;

  do
  {
    Selector selCurr = M.getSelector() ;

    //addItems:
    if ( selCurr.getNumArgs() != 1 )
    {
      // Unlikely to be of concerned
      break ;
    }
    
    //addItems:
    if ( selCurr.getIdentifierInfoForSlot(0) != m_piiAddItems )
    {
      break ;
    }
    
    ProgramStateRef pProgState = C.getState() ;
    const LocationContext *pLCtx = C.getLocationContext() ;
   
    //Check the value for "items" parameter (1st)
    SVal argVal = pProgState ->getSVal( M.getArgExpr(0), pLCtx ) ;

    if ( argVal.isUnknownOrUndef() || argVal.isZeroConstant() )
    {
      break ; 
    }

    //Get receiver as symbol
    SymbolRef pSymInstance = M.getReceiverSVal().getAsSymbol() ;

    if ( !pSymInstance )
    {
      break ; 
    }

    pRet = pSymInstance ; 
  
  } while (_PASSING_) ;
  
  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;

  return pRet ;
}

SymbolRef iOSAppSecLeakingPasteboardChecker::checkProperties( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const
{
  SymbolRef pRet = NULL ;
  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;

  do
  {
    // No property to check
    if ( !m_vPropertyIdPtrs.size() )
    {
      break ;
    }    
    
    Selector selCurr = M.getSelector() ;

    // Properties does not have arguments 
    if ( selCurr.getNumArgs() )
    {
      break ;
    }

    ProgramStateRef pProgState = C.getState() ;
    const ObjCMethodDecl *pMD = M.getDecl() ;

    if ( !pMD )
    {
      break ;
    }

    const ObjCPropertyDecl *pPropDecl = pMD ->findPropertyDecl() ;

    if ( !pPropDecl )
    {
      //MSEC_DEBUG("redwud: ","!pPropDecl\n") ;
      break ;
    }

    const IdentifierInfo *pID = pPropDecl ->getDefaultSynthIvarName( Ctx ) ;

    if ( !pID )
    {
      break ;
    }
    
    for ( IdPtrVectorType::iterator pItem = m_vPropertyIdPtrs.begin(), pEndItem = m_vPropertyIdPtrs.end();
          pItem != pEndItem; pItem++ )
    {
      if ( pID != (*pItem) )
      {
        continue ; 
      }

      //Get receiver as symbol
      SymbolRef pSymInstance = M.getReceiverSVal().getAsSymbol() ;

      if ( !pSymInstance )
      {
        MSEC_DEBUG("redwud: ","!pSymInstance\n") ;
        break ; 
      }

      pRet = pSymInstance ;
    }

  } while (_PASSING_) ;
  
  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;

  return pRet ;
}

//NOTE: This method is made to be separated because ASTContext is not available during instatiation
void iOSAppSecLeakingPasteboardChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
  do
  {
    //redwud: prevent the following to from gettting reinitialized
    if ( m_piiUIPasteboard )
    {
      break ;      
    }
 
    MSEC_DEBUG_FUNC("redwud: ","ENTER") ;

    m_piiUIPasteboard      = &Ctx.Idents.get("UIPasteboard") ;
    m_piiSetData           = &Ctx.Idents.get("setData") ;
    m_piiForPasteboardType = &Ctx.Idents.get("forPasteboardType") ;
    m_piiSetValue          = &Ctx.Idents.get("setValue") ; 
    m_piiAddItems          = &Ctx.Idents.get("addItems") ;

    // Deal with properties at once

    StringRef aProperties[] = {
                "_items"
               ,"_string"
               ,"_strings"
               ,"_image"
               ,"_images"
               ,"_URL"
               ,"_URLs"

             //It seems these are benign
               //,"_color"
               //,"_colors"
             } ;

    m_vPropertyIdPtrs.clear() ;

    for ( int iCtr = 0; iCtr < _countof( aProperties ); iCtr++ )
    {
      IdentifierInfo *pID = &Ctx.Idents.get( aProperties[ iCtr ] ) ;

      if ( !pID )
      {
        continue ;
      }
      
      m_vPropertyIdPtrs.push_back( pID ) ;
    }

    MSEC_DEBUG_FUNC("redwud: ","EXIT") ;

  } while (_PASSING_) ;
}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecLeakingPasteboardChecker(CheckerManager &rMgr) 
{
  rMgr.registerChecker< iOSAppSecLeakingPasteboardChecker >();
}

