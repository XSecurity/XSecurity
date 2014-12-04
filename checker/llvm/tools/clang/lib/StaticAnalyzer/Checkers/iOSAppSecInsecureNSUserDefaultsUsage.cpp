//===-- iOSAppSecInsecureNSUserDefaultsUsageChecker.cpp -----------------------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// The checker should be able to detect the following sample code,
// the blame point should be on synchronize.

/*

    Bad Example:
 
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:self.username.text forKey:@"username"];
    [defaults setObject:self.password.text forKey:@"password"];
    [defaults synchronize];

*/

//
// Implementation Note:
//

// - Detect pre message "[defaults setObject:self.username.text forKey:@"password"];" 
//   - Record [query] symbol associated with a sensitive name for a key
//   - Consider if an object does not matche the regex pattern of sensitive information, then release the association on that [query] symbol
// 
// - Detect post message to "[defaults synchronize];"
//   - Check if [defaults] is recorded as one of the above then report security warning
//   - Also check message for synchronize
//
//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecInsecureNSUserDefaultsUsageChecker

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

//#define MSEC_DBG
#include "clang/StaticAnalyzer/Core/MSecCommon.h"

#include "SensitiveInfo.h"

using namespace clang ;
using namespace ento ;
using namespace msec_cmn ; 

namespace 
{

  typedef SMSecState NSUserDefaultsState ; 

  class iOSAppSecInsecureNSUserDefaultsUsageChecker 
    : public Checker< 
                      check::PreObjCMessage 
                    , check::PostObjCMessage
                    , check::DeadSymbols
                    > 
  {
 
  protected:
    mutable IdentifierInfo *m_piiNSUserDefaults, *m_piiSetObject,
                           *m_piiForKey, *m_piiSynchronize ; 

    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;
  
    // Is the anObject in setObject:forKey: insecure?
    bool isInsecureObject( const SVal &svalObject ) const ;   
   
    // Is pSymbol one of the previously recorded pSymbol that is marked as not secure 
    bool isInsecureSymbol( const SymbolRef pSymbol, const ProgramStateRef pProgState ) const ; 
   
  public:
    // Default Constructor
    iOSAppSecInsecureNSUserDefaultsUsageChecker() ;

    void checkPreObjCMessage (const ObjCMethodCall &M, CheckerContext &C) const ;

    void checkPostObjCMessage (const ObjCMethodCall &M, CheckerContext &C) const ;
    
    /// A “dead” symbol can never be referenced again along this path 
    /// • Checkers can be notified when symbols die
    //redwud: In simple terms the var got out of scope
    void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

  };
  
} // end anonymous namespace
  
/// The state of the checker is a map from tracked stream symbols to their
/// state. Let's store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, NSUserDefaultsState)

namespace 
{
  //redwud: This one is enigmatic, can't find any reference to it. 
  class StopTrackingCallback : public SymbolVisitor 
  {
   protected:
    ProgramStateRef m_state;

   public:

    StopTrackingCallback(ProgramStateRef st) : m_state(st) {}
   
    ProgramStateRef getState() const 
    {
      MSEC_DEBUG( "redwud: ", "getState() is called!!!! but when?" ) ; 
      return m_state; 
    }
  
    bool VisitSymbol(SymbolRef sym)
    {
      MSEC_DEBUG( "redwud: ", "VisitSymbol() is called!!!! but when?" ) ; 
      m_state = m_state ->remove< StreamMap >(sym);
      return true;
    }
  };
} // end anonymous namespace


//red: Default Constructor
iOSAppSecInsecureNSUserDefaultsUsageChecker::iOSAppSecInsecureNSUserDefaultsUsageChecker() 
  : m_piiNSUserDefaults(NULL)
  , m_piiSetObject(NULL)
  , m_piiForKey(NULL)
  , m_piiSynchronize(NULL)
{
  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType( "Insecure NSUserDefaults Usage",
                                            "Insecure Data Storage"));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true );
}

/// Process call to NSMutableArray:setObject:forKey: 
void iOSAppSecInsecureNSUserDefaultsUsageChecker::checkPreObjCMessage 
  (const ObjCMethodCall &M, CheckerContext &C) const
{
  MSEC_DEBUG_FUNC("red:","ENTER") ;

  do
  {
    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      break ;
    }

    MSEC_DEBUG("pRxInterface ->getIdentifier()->getName():", pRxInterface ->getIdentifier()->getName());
 
    //NSUserDefaults
    if ( pRxInterface ->getIdentifier() != m_piiNSUserDefaults )
    {
      break ;
    } 

    ASTContext &Ctx = C.getASTContext() ;
    Selector selCurr = M.getSelector() ; 

    initIdentifierInfo( Ctx ) ;

    //setObject 
    IdentifierInfo *piiSetObject = selCurr.getIdentifierInfoForSlot(0) ;  

    if ( piiSetObject != m_piiSetObject )
    {
       break ;
    }
    
    //forKey
    IdentifierInfo *piiForKey = selCurr.getIdentifierInfoForSlot(1) ;

    if ( piiForKey != m_piiForKey )
    {
       break ;
    }
    
    //MSEC_DEBUG("red: ", "'" << selCurr.getAsString() << "' num args: " << selCurr.getNumArgs() ) ;
    if ( selCurr.getNumArgs() != 2 )
    {
      // Unlikely to be of concerned 
      break ;
    }

    ProgramStateRef progState = C.getState() ;
    const LocationContext *pLCtx = C.getLocationContext() ; 

    //Get the value for "aKey" parameter (2nd)
    // Checking this first because checking the first parameter takes a bit longer    
    const Expr *pKeyExpr = M.getArgExpr(1) ;
    SVal argValKey = progState ->getSVal( pKeyExpr, pLCtx ) ;

    CSensitiveInfo &rSenInfo = CSensitiveInfo::create() ;
    std::string keyString = CMSecCommon::getStringFromSVal(argValKey);

    if ( keyString.empty() )
    {
      break ;
    }

    if ( !rSenInfo.isSensitive( keyString ))
    {
        MSEC_DEBUG( "redwud: ", "!Sensitive :" << keyString) ;
        break ; 
    }

    //Get the value for "anObject" parameter (1st)
    const Expr *pObjExpr = M.getArgExpr(0) ;
    SVal argValAnObject = progState ->getSVal( pObjExpr, pLCtx ) ;

    //Get receiver as symbol, should be used in either condition
    SymbolRef pSymQuery = M.getReceiverSVal().getAsSymbol() ;

    if ( !pSymQuery )
    {
      // redwud: Can't save empty receiver symbol,
      // so there is no point of moving on, 
      // there must be something wrong with this
      break ;
    }

    //Idea: if [query] is currently being tracked change it to different status, e.g. secure
    //      if not tracked add new secure state

    bool bInsecureObject = isInsecureObject( argValAnObject ) ; 
    bInsecureObject = true;

    progState = progState ->set <StreamMap>( pSymQuery, bInsecureObject ? 
      NSUserDefaultsState::getNotSecure() : NSUserDefaultsState::getSecure() ) ;   

    // Add transition of state
    //red: it seems that the states are transitioned at some point
    C.addTransition( progState ) ;

    MSEC_DEBUG( "red: ", "Finish checking!" ) ; 
  } while (_PASSING_) ;


  MSEC_DEBUG_FUNC("red:","EXIT") ;
}


/// Process SecItemAdd() and SecItemUpdate().

//Interfaces:
// OSStatus SecItemAdd (
//    CFDictionaryRef attributes,
//    CFTypeRef *result
// ); 

// OSStatus SecItemUpdate (
//    CFDictionaryRef query,
//    CFDictionaryRef attributesToUpdate
// );

// Checking for SecItemAdd and SecItemUpdate, no particular reason for assigning it to PostCall
void iOSAppSecInsecureNSUserDefaultsUsageChecker::checkPostObjCMessage (const ObjCMethodCall &M, 
  CheckerContext &C) const
{

  MSEC_DEBUG_FUNC("red:","ENTER") ;

  do
  {

    ASTContext &Ctx = C.getASTContext() ;
    Selector selCurr = M.getSelector() ; 

    initIdentifierInfo( Ctx ) ;

    //setObject 
    IdentifierInfo *piiSynchronize = selCurr.getIdentifierInfoForSlot(0) ;  
    
    //We do away with array because it's only two of them and it
    //will break the while..passing pattern  
    if ( piiSynchronize != m_piiSynchronize )
    {  
      break ;
    }

    SymbolRef pSymToCheck = M.getReceiverSVal().getAsSymbol() ;

    if ( !pSymToCheck )
    {
      break ;
    }

    ProgramStateRef pProgState = C.getState() ; 
    
    if ( !isInsecureSymbol( pSymToCheck, pProgState ) ) 
    {
      break ;
    }
 
    //Report this instance
    CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
      , *m_pInsecureInstBugType, "The app seems to store sensitive data in NSUserDefaults without encrypting it." ) ;
  
  } while ( _PASSING_ ) ;

  MSEC_DEBUG_FUNC("red:","EXIT") ;

}


bool iOSAppSecInsecureNSUserDefaultsUsageChecker::isInsecureObject( const SVal &svalObject ) const
{
  bool bRet = false ;

  do
  {
  
    std::string szID = CMSecCommon::getStringFromSVal( svalObject ) ; 
    
    if ( szID.empty() )
    {
      break ;
    }
    
    const char *aszVulnObjects[] = { 
      "kSecAttrAccessibleAlways"
     ,"kSecAttrAccessibleAlwaysThisDeviceOnly"
     ,"kSecAttrAccessibleAfterFirstUnlock"
     ,"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
      } ;
    
    for ( int iCtr = 0; iCtr < _countof_strict( aszVulnObjects, int ); iCtr++ )
    {
      if ( szID.find( aszVulnObjects[iCtr] ) != std::string::npos )
      {
        bRet = true ;
        break ;
      }
    }

  } while( _PASSING_ ) ;

  return bRet ;
} 

//Make this generic by adding templates to it
// e.g. passing it to <StreamMap> and NSUserDefaultsState
bool iOSAppSecInsecureNSUserDefaultsUsageChecker::isInsecureSymbol( const SymbolRef pSymbol, 
       const ProgramStateRef pProgState ) const
{
  MSEC_DEBUG_FUNC("red:","ENTER") ;

  bool bRet = false ;

  do
  {
    if ( !pSymbol || !pProgState )
    {
      break ;
    }
    
    const NSUserDefaultsState *pNSUserDefaultsState = pProgState ->get <StreamMap> ( pSymbol ) ; 
    
    if ( !pNSUserDefaultsState )
    {
      break ;
    }
      
    bRet = pNSUserDefaultsState ->isNotSecure() ;

  } while( _PASSING_ ) ;

  MSEC_DEBUG_FUNC("red:","EXIT") ;

  return bRet ;
} 


// Use not for leaks but useful to remove our stored symbols 
void iOSAppSecInsecureNSUserDefaultsUsageChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                           CheckerContext &C) const
{
  ProgramStateRef pProgState = C.getState() ;
  StreamMapTy TrackedStreams = pProgState ->get<StreamMap>() ;
 
  for (StreamMapTy::iterator I = TrackedStreams.begin(),
                             E = TrackedStreams.end(); I != E; ++I) 
  {
    SymbolRef Sym = I ->first ;
    bool IsSymDead = SymReaper.isDead( Sym ) ;

    // Remove the dead symbol from the streams map.
    if ( IsSymDead )
    {
      pProgState = pProgState -> remove<StreamMap>( Sym ) ;
    }
  }

  C.addTransition( pProgState ) ;
}


//NOTE: This method is made to be separated because ASTContext is not available during instatiation
void iOSAppSecInsecureNSUserDefaultsUsageChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
 
  do
  {
    //red: prevent the following to from gettting reinitialized
    if ( m_piiNSUserDefaults )
    {
      break ;      
    }

    m_piiNSUserDefaults = &Ctx.Idents.get("NSUserDefaults") ;

    m_piiSetObject     = &Ctx.Idents.get("setObject") ;     
    m_piiForKey        = &Ctx.Idents.get("forKey") ;

    m_piiSynchronize    = &Ctx.Idents.get("synchronize") ;

  } while (_PASSING_) ;

}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecInsecureNSUserDefaultsUsageChecker(CheckerManager &mgr) 
{
  mgr.registerChecker<iOSAppSecInsecureNSUserDefaultsUsageChecker>();
}

