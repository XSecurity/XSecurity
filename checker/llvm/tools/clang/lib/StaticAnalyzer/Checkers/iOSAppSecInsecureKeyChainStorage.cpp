//===-- iOSAppSecInsecureKeyChainStorageChecker.cpp -----------------------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// The checker should be able to detect the following sample code,
// the blame point should be on SecItemAdd() also if SecItemUpdate() is called instead.

/*

    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    NSString *szAccount = @"AccountName" ;
    NSString *szInputString = @"My Crazy Input String" ;
    
    
    [query setObject: (id)CFBridgingRelease(kSecClassGenericPassword) forKey: (id)CFBridgingRelease(kSecClass) ] ;
    
    [query setObject: szAccount forKey:(id) CFBridgingRelease(kSecAttrAccount) ] ;

    // Initial instance of this vulnerability
    [query setObject: (id)CFBridgingRelease(kSecAttrAccessibleAlways) forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;

    OSStatus error = SecItemAdd((CFDictionaryRef)CFBridgingRetain(query), NULL);

*/

//
// Implementation Note:
//

// - Detect pre message "[query setObject: (id)CFBridgingRelease(kSecAttrAccessibleAlways) forKey: (id)CFBridgingRelease(kSecAttrAccessible) ] ;" 
//   - Record [query] symbol associated with kSecAttrAccessibleAlways
//   - Consider object is not one of the following, then release the association on that [query] symbol
//     kSecAttrAccessibleAlways
//     kSecAttrAccessibleAlwaysThisDeviceOnly
//     kSecAttrAccessibleAfterFirstUnlock
//     kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
// 
// - Detect post call to "SecItemAdd((CFDictionaryRef)CFBridgingRetain(query), NULL); "
//   - Check if [query] is recorded as one of the above then report security warning
//   - Also check call for SecItemUpdate() and do the same thing
// 
// - Detect post call to "SecItemDelete( query )"
//   - Check if [query] is recorded then remove it from the map
//
// Future TODO:
// - Add determination if the info being saved is sensitive or not
// - Consider if the following methods are called with the target symbol (NSMutableDictionary)
//   – removeObjectForKey:
//   – removeAllObjects
//   – removeObjectsForKeys:

//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecInsecureKeyChainStorageChecker

#include "ClangSACheckers.h"
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
  //redwud: Status of the file handle?
  // This dude here is one is mapped to the symbol and being queried later on
  // to see it's status  
  typedef SMSecState KeyChainState ; 

  //redwud: The main job of this class is to receive call backs for the points
  //        of interest for this checker.
  //        This will mostlikely have one instance. 
  class iOSAppSecInsecureKeyChainStorageChecker 
    : public Checker< 
                      check::PreObjCMessage 
                    , check::PostCall
                    , check::DeadSymbols
                    > 
  {
 
  protected:
    mutable IdentifierInfo *m_piiSecItemAdd, *m_piiSecItemUpdate, *m_piiNSMutableDictionary,
                           *m_piiSetObject, *m_piiForKey  ; 

    const StringRef       m_szReportDesc ;    
    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;
  
    // Is the anObject in setObject:forKey: insecure?
    bool isInsecureObject( const SVal &svalObject ) const ;   
   
    // Is pSymbol one of the previously recorded pSymbol that is marked as not secure 
    bool isInsecureSymbol( const SymbolRef pSymbol, const ProgramStateRef pProgState ) const ; 
   
  public:
    //redwud: Default Constructor
    iOSAppSecInsecureKeyChainStorageChecker() ;

    void checkPreObjCMessage (const ObjCMethodCall &M, CheckerContext &C) const ;
  
    /// Process SecItemAdd() and SecItemUpdate().
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    
    /// A “dead” symbol can never be referenced again along this path 
    /// • Checkers can be notified when symbols die
    //redwud: In simple terms the var got out of scope
    void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;
  };
  
} // end anonymous namespace
  
/// The state of the checker is a map from tracked stream symbols to their
/// state. Let's store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, KeyChainState)

//FIXME: Do the TODO part.
//TODO: Confirm where this thing is being called, use PrintStack() something if necessary  
namespace 
{
  //redwud: This one is enigmatic, can't find any reference to it. 
  class StopTrackingCallback : public SymbolVisitor 
  {
   protected:
    ProgramStateRef m_state;

   public:
    //redwud: Copy Constructor
    StopTrackingCallback(ProgramStateRef st) : m_state(st) {}
   
    ProgramStateRef getState() const 
    {
      MSEC_DEBUG( "redwud: ", "getState() is called!!!! but when?" ) ; 
      return m_state; 
    }
  
    bool VisitSymbol(SymbolRef sym)
    {
      MSEC_DEBUG( "redwud: ", "getState() is called!!!! but when?" ) ; 
      m_state = m_state ->remove< StreamMap >(sym);
      return true;
    }
  };
} // end anonymous namespace


//redwud: Default Constructor
iOSAppSecInsecureKeyChainStorageChecker::iOSAppSecInsecureKeyChainStorageChecker() 
  : m_piiSecItemAdd         (NULL)
  , m_piiSecItemUpdate      (NULL)
  , m_piiNSMutableDictionary(NULL)
  , m_piiSetObject          (NULL)
  , m_piiForKey             (NULL)
  , m_szReportDesc          ("The information is stored in the Keychain with weak accessibility options.")  
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;

  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType( "Keychain related vulnerability",
                                            "Insecure Data Storage"));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true );

  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
}

//FIXME: Consider other methods than setObject like dictionaryWithObjectsAndKeys
/// Process call to NSMutableArray:setObject:forKey: 
void iOSAppSecInsecureKeyChainStorageChecker::checkPreObjCMessage 
  (const ObjCMethodCall &M, CheckerContext &C) const
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;

  do
  {
    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      break ;
    }

    ASTContext &Ctx = C.getASTContext() ;
    Selector selCurr = M.getSelector() ; 

    initIdentifierInfo( Ctx ) ;

    //TODO: Check this with property, this might not work on it    
    //NSMutableDictionary 
    if ( pRxInterface ->getIdentifier() != m_piiNSMutableDictionary )
    {
      break ;
    } 

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
    
    // MSEC_DEBUG("redwud: ", "'" << selCurr.getAsString() << "' num args: " << selCurr.getNumArgs() ) ;
    if ( selCurr.getNumArgs() != 2 )
    {
      // Unlikely to be of concerned 
      break ;
    }

    ProgramStateRef pProgState = C.getState() ;
    const LocationContext *pLCtx = C.getLocationContext() ; 

    //Get the value for "aKey" parameter (2nd)
    // Checking this first because checking the first parameter takes a bit longer    
    const Expr *pKeyExpr = M.getArgExpr(1) ;
    SVal argValKey = pProgState ->getSVal( pKeyExpr, pLCtx ) ;

    if ( !CMSecCommon::isSValContains( argValKey, "kSecAttrAccessible" ) )
    {
      // Not of concern
      break ; 
    }

    //Get the value for "anObject" parameter (1st)
    const Expr *pObjExpr = M.getArgExpr(0) ;
    SVal argValAnObject = pProgState ->getSVal( pObjExpr, pLCtx ) ;

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

    pProgState = pProgState ->set <StreamMap>( pSymQuery, bInsecureObject ? 
      KeyChainState::getNotSecure() : KeyChainState::getSecure() ) ;   

    // Add transition of state
    //redwud: it seems that the states are transitioned at some point
    C.addTransition( pProgState ) ;

    MSEC_DEBUG( "redwud: ", "Finish checking!" ) ; 
  } while (_PASSING_) ;


  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
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
void iOSAppSecInsecureKeyChainStorageChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const 
{
  do
  {
    initIdentifierInfo( C.getASTContext() ) ;

    //redwud: Obviously it is what it is
    if ( !Call.isGlobalCFunction() )
    {
      break ;
    }

    const IdentifierInfo *pCalleeIdent = Call.getCalleeIdentifier() ; 

    // for SecITemAdd() by default
    unsigned int uiParam = 0 ; 
    
    //We do away with array because it's only two of them and it
    //will break the while..passing pattern  
    if ( pCalleeIdent != m_piiSecItemAdd )
    {  
      if ( (pCalleeIdent != m_piiSecItemUpdate) )
      {
        break ;
      }
      else
      {
        uiParam = 1 ;
      }
    }
    
    //Get the query parameter
    //Check if it was recorded as not secure
    //Then create a report
    //Else do nothing

    // Use new method to reuse for checking each parameters, 
    // 1st param for SecItemAdd(), 2nd param for SecItemUpdate() 

    // Get the symbolic value corresponding to the "attributes" parameter.
    SymbolRef pSymToCheck = Call.getArgSVal( uiParam ).getAsSymbol() ;

    //rewud: Not sure how to interpret this, it seems there are no
    //       no symbol for the first parameter 
    if ( !pSymToCheck )
    {
      break ;
    }

    ProgramStateRef pProgState = C.getState() ; 
    
    if ( !isInsecureSymbol( pSymToCheck, pProgState ) ) 
    {
      break ;
    }

    if ( !m_pInsecureInstBugType )
    {
      MSEC_DEBUG( "redwud: ", "!m_pInsecureInstBugType" ) ;
      break ;
    }
 
    //Report this instance
    CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
      , *m_pInsecureInstBugType, m_szReportDesc ) ;
  
  } while ( _PASSING_ ) ;

}


bool iOSAppSecInsecureKeyChainStorageChecker::isInsecureObject( const SVal &svalObject ) const
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
// e.g. passing it to <StreamMap> and KeyChainState
bool iOSAppSecInsecureKeyChainStorageChecker::isInsecureSymbol( const SymbolRef pSymbol, 
       const ProgramStateRef pProgState ) const
{
  bool bRet = false ;

  do
  {
    if ( !pSymbol || !pProgState )
    {
      break ;
    }
    
    const KeyChainState *pKeyChainState = pProgState ->get <StreamMap> ( pSymbol ) ; 
    
    if ( !pKeyChainState )
    {
      break ;
    }
      
    bRet = pKeyChainState ->isNotSecure() ;

  } while( _PASSING_ ) ;

  return bRet ;
} 


// Use not for leaks but useful to remove our stored symbols 
void iOSAppSecInsecureKeyChainStorageChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                           CheckerContext &C) const
{
  ProgramStateRef pProgState = C.getState() ;
  StreamMapTy TrackedStreams = pProgState ->get<StreamMap>() ;
 
  for (StreamMapTy::iterator I = TrackedStreams.begin(),
                             E = TrackedStreams.end(); I != E; ++I) 
  {
    SymbolRef pSymbol = I ->first ;

    // Remove the dead symbol from the streams map.
    if ( SymReaper.isDead( pSymbol ) )
    {
      pProgState = pProgState -> remove<StreamMap>( pSymbol ) ;
    }
  }

  C.addTransition( pProgState ) ;
}


//NOTE: This method is made to be separated because ASTContext is not available during instatiation
void iOSAppSecInsecureKeyChainStorageChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
 
  do
  {
    //redwud: prevent the following to from gettting reinitialized
    if ( m_piiSecItemAdd )
    {
      break ;      
    }
    MSEC_DEBUG_FUNC("redwud:","ENTER") ;

    m_piiSecItemAdd           = &Ctx.Idents.get("SecItemAdd") ;
    m_piiSecItemUpdate        = &Ctx.Idents.get("SecItemUpdate") ;
    m_piiNSMutableDictionary  = &Ctx.Idents.get("NSMutableDictionary") ;

    m_piiSetObject            = &Ctx.Idents.get("setObject") ;     
    m_piiForKey               = &Ctx.Idents.get("forKey") ;

    MSEC_DEBUG_FUNC("redwud:","EXIT") ;
  } while (_PASSING_) ;

}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecInsecureKeyChainStorageChecker(CheckerManager &mgr) 
{
  mgr.registerChecker<iOSAppSecInsecureKeyChainStorageChecker>();
}

