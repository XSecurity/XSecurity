//===-- iOSAppSecPermanentCredentialChecker.cpp -----------------------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// The checker should be able to detect the following sample code,
// the blame point should be on setDefaultCredential:forProtectionSpace: also if setCredential:forProtectionSpace: is called instead.

/*

===========
Bad Example
===========
 
    self.loginProtectionSpace = [[NSURLProtectionSpace alloc]
                                                  initWithHost:@"somehost"
                                                  port:80
                                                  protocol:@"https"
                                                  realm:@"somehost"
                                                  authenticationMethod:NSURLAuthenticationMethodDefault];
    
    NSURLCredential *credential = [NSURLCredential credentialWithUser:self.username.text password:self.password.text
                                   persistence:NSURLCredentialPersistencePermanent];
    
    [[NSURLCredentialStorage sharedCredentialStorage] setCredential:credential
                                                      forProtectionSpace:self.loginProtectionSpace];

    -----------------------------------------------------------------------------------------------------------------

    NSURLCredential *credential = [[NSURLCredential alloc] initWithUser:self.username.text password:self.password.text 
                                   persistence:NSURLCredentialPersistencePermanent];
    
    [[NSURLCredentialStorage sharedCredentialStorage] setCredential:credential
                                                      forProtectionSpace:self.loginProtectionSpace];


===========================
Related Classes and Methods
===========================

---------------------
NSURLCredential Class
---------------------

 Class Methods:
  + credentialWithUser:password:persistence:
    Creates and returns an NSURLCredential object for internet password authentication with a given user name and password using a given persistence setting.
  + credentialWithIdentity:certificates:persistence:
    Creates and returns an NSURLCredential object for client certificate authentication with a given identity and a given array of client certificates using a given persistence setting

 Instance Methods:
  – initWithIdentity:certificates:persistence:
  – initWithUser:password:persistence:

 Reference:
  https://developer.apple.com/library/ios/documentation/cocoa/reference/foundation/Classes/NSURLCredential_Class/Reference/Reference.html

----------------------------
NSURLCredentialStorage Class
----------------------------

 Instance Methods:
  - setDefaultCredential:forProtectionSpace:
  – setCredential:forProtectionSpace:

 Refecence: 
  https://developer.apple.com/library/ios/documentation/cocoa/reference/foundation/Classes/NSURLCredentialStorage_Class/Reference/Reference.html


*/

//
// Implementation Note:
//

// - Detect pre message like
//       "NSURLCredential *credential = [NSURLCredential credentialWithUser:self.username.text password:self.password.text
//                  persistence:NSURLCredentialPersistencePermanent];"
//   - Record [credential] symbol associated with NSURLCredentialPersistencePermanent for persisitence
//   - Consider if an object does not matche the following regex, then release the association on that [credential] symbol
//     
// - Detect post message like
//      "[[NSURLCredentialStorage sharedCredentialStorage] setCredential:credential
//                                                      forProtectionSpace:self.loginProtectionSpace];"
//   - Check if [credential] is recorded as one of the above then report security warning
//   - Also check message for synchronize
//
//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecPermanentCredentialChecker

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

  typedef SMSecState NSURLCredentialState ; 

  class iOSAppSecPermanentCredentialChecker 
    : public Checker< 
                      check::PreObjCMessage 
                    , check::PostObjCMessage
                    , check::DeadSymbols
                    > 
  {
 
  protected:
    mutable IdentifierInfo *m_piiNSURLCredential, *m_piiNSURLCredentialStorage, *m_piiSetCredential ; 

    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;
  
    // Is the anObject in setValue:forKey: insecure?
    bool isInsecureObject( const SVal &svalObject ) const ;   
   
    // Is pSymbol one of the previously recorded pSymbol that is marked as not secure 
    bool isInsecureSymbol( const SymbolRef pSymbol, const ProgramStateRef pProgState ) const ; 
   
  public:
    // Default Constructor
    iOSAppSecPermanentCredentialChecker() ;

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
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, NSURLCredentialState)

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
      MSEC_DEBUG( "red: ", "getState() is called!!!! but when?" ) ; 
      return m_state; 
    }
  
    bool VisitSymbol(SymbolRef sym)
    {
      MSEC_DEBUG( "red: ", "VisitSymbol() is called!!!! but when?" ) ; 
      m_state = m_state ->remove< StreamMap >(sym);
      return true;
    }
  };
} // end anonymous namespace


// Default Constructor
iOSAppSecPermanentCredentialChecker::iOSAppSecPermanentCredentialChecker() 
  : m_piiNSURLCredential(NULL)
  , m_piiNSURLCredentialStorage(NULL)
  , m_piiSetCredential(NULL)
{
  // Initialize the bug type, no sinks in this vulnerability.
  m_pInsecureInstBugType.reset(new BugType( "Insecure Plist Usage",
                                            "Insecure Data Storage"));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true );

}


void iOSAppSecPermanentCredentialChecker::checkPreObjCMessage 
  (const ObjCMethodCall &M, CheckerContext &C) const
{
  MSEC_DEBUG_FUNC("red:","ENTER") ;

  do
  {
    ASTContext &Ctx = C.getASTContext() ;
    Selector selCurr = M.getSelector() ; 

    initIdentifierInfo( Ctx ) ;

    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      break ;
    }
  
    // NSURLCredentialStorage
    if ( m_piiNSURLCredentialStorage != pRxInterface ->getIdentifier() )
    {
      break ;
    } 

    if (selCurr.getAsString() != "setCredential:forProtectionSpace:" &&
        selCurr.getAsString() != "setDefaultCredential:forProtectionSpace:")
    {
      break;
    }

    ProgramStateRef progState = C.getState() ;
    const LocationContext *pLCtx = C.getLocationContext() ; 

    const Expr *pCredentialExpr = M.getArgExpr(0) ;
    SVal argValCredential = progState ->getSVal( pCredentialExpr, pLCtx ) ;
    SymbolRef pSymToCheck = argValCredential.getAsSymbol();

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
      , *m_pInsecureInstBugType, "The credential is stored in the keychain permanently." ) ;
  
  } while (_PASSING_) ;


  MSEC_DEBUG_FUNC("red:","EXIT") ;
}



void iOSAppSecPermanentCredentialChecker::checkPostObjCMessage (const ObjCMethodCall &M, 
  CheckerContext &C) const
{

  MSEC_DEBUG_FUNC("red:","ENTER") ;

  do
  {

    initIdentifierInfo( C.getASTContext() ) ;

    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      break ;
    }

    MSEC_DEBUG("pRxInterface ->getIdentifier()->getName():", pRxInterface ->getIdentifier()->getName());
 
    //NSURLCredential
    if ( pRxInterface ->getIdentifier() != m_piiNSURLCredential )
    {
      break ;
    } 

    Selector selCurr = M.getSelector() ; 

    if (selCurr.getAsString() != "credentialWithUser:password:persistence:" &&
        selCurr.getAsString() != "credentialWithIdentity:certificates:persistence:" &&
        selCurr.getAsString() != "initWithIdentity:certificates:persistence:" &&
        selCurr.getAsString() != "initWithUser:password:persistence:")
    {
      break;
    }
    
    //MSEC_DEBUG("red: ", "'" << selCurr.getAsString() << "' num args: " << selCurr.getNumArgs() ) ;
    if ( selCurr.getNumArgs() != 3 )
    {
      // Unlikely to be of concerned 
      break ;
    }

    ProgramStateRef progState = C.getState() ;
    const LocationContext *pLCtx = C.getLocationContext() ; 

    //Get the value for "persistence" parameter (3rd)
    // Checking this first because checking the first parameter takes a bit longer    
    const Expr *pKeyExpr = M.getArgExpr(2) ;
    SVal argValKey = progState ->getSVal( pKeyExpr, pLCtx ) ;

    //
    // typedef NS_ENUM(NSUInteger, NSURLCredentialPersistence) {
    //  NSURLCredentialPersistenceNone,
    //  NSURLCredentialPersistenceForSession,
    //  NSURLCredentialPersistencePermanent, <- This is what we should detect
    //  NSURLCredentialPersistenceSynchronizable
    // };
    //
    if (!argValKey.isConstant(2))
    {
      break;
    }

    //Get the return value as symbol, should be used in either condition
    SymbolRef pSymQuery = M.getReturnValue().getAsSymbol() ;
    if ( !pSymQuery )
    {
      // redwud: Can't save empty receiver symbol,
      // so there is no point of moving on, 
      // there must be something wrong with this
      break ;
    }

    progState = progState ->set <StreamMap>( pSymQuery, 
      NSURLCredentialState::getNotSecure()) ; 

    // Add transition of state
    //redwud: it seems that the states are transitioned at some point
    C.addTransition( progState ) ;

    MSEC_DEBUG( "red: ", "Finish checking!" ) ; 


  } while ( _PASSING_ ) ;

  MSEC_DEBUG_FUNC("red:","EXIT") ;

}


//Make this generic by adding templates to it
// e.g. passing it to <StreamMap> and NSURLCredentialState
bool iOSAppSecPermanentCredentialChecker::isInsecureSymbol( const SymbolRef pSymbol, 
       const ProgramStateRef pProgState ) const
{
  bool bRet = false ;

  do
  {
    if ( !pSymbol || !pProgState )
    {
      break ;
    }
    
    const NSURLCredentialState *pNSURLCredentialState = pProgState ->get <StreamMap> ( pSymbol ) ; 
    
    if ( !pNSURLCredentialState )
    {
      break ;
    }
      
    bRet = pNSURLCredentialState ->isNotSecure() ;

  } while( _PASSING_ ) ;

  return bRet ;
} 


// Use not for leaks but useful to remove our stored symbols 
void iOSAppSecPermanentCredentialChecker::checkDeadSymbols(SymbolReaper &SymReaper,
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
void iOSAppSecPermanentCredentialChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
  do
  {
    //red: prevent the following to from gettting reinitialized
    if ( m_piiNSURLCredential )
    {
      break ;      
    }

    m_piiNSURLCredential = &Ctx.Idents.get("NSURLCredential") ;
    m_piiNSURLCredentialStorage = &Ctx.Idents.get("NSURLCredentialStorage") ;
    m_piiSetCredential    = &Ctx.Idents.get("setCredential") ;

  } while (_PASSING_) ;

}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecPermanentCredentialChecker(CheckerManager &mgr) 
{
  mgr.registerChecker<iOSAppSecPermanentCredentialChecker>();
}

