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

// 1st Instance
[NSURLRequest setAllowsAnyHTTPSCertificate:YES forHost:[URL host]];

// 2nd Instance
NSURLAuthenticationChallenge *challenge = nil;
[challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];

// 3rd Insance
NSMutableDictionary *properties = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                            [NSNumber numberWithBool:YES], kCFStreamSSLAllowsExpiredCertificates,
                            [NSNumber numberWithBool:YES], kCFStreamSSLAllowsAnyRoot, [NSNumber numberWithBool:NO], 
                            kCFStreamSSLValidatesCertificateChain, kCFNull,kCFStreamSSLPeerName, nil] ;

UInt8 pData[] = "this is data" ;

CFReadStreamRef inCfStream = CFReadStreamCreateWithBytesNoCopy( kCFAllocatorDefault, pData, _countof(pData), kCFAllocatorNull )  ;

if ( CFReadStreamSetProperty(inCfStream, kCFStreamPropertySSLSettings, (CFTypeRef)properties) == FALSE)
{
    NSLog(@"Failed to set SSL properties on read stream.");
}

*/
//
// Implementation Note:
//

//// 2nd Instance
//
// Under NSURLConnectionDelegate or NSURLConnection 
// - Check if continueWithoutCredentialForAuthenticationChallenge is called in every NSURLAuthenticationChallenge variable's sender (NSURLAuthenticationChallengeSender) 
// 
// Affected methods:
// - (void)connection:(NSURLConnection *)connection didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
// - (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
// - (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
// 
// Note: Originally the only affected method is didReceiveAuthenticationChallenge 

//
// Alternative Implementation for 2nd Instance
//

//- Detect if message is continueWithoutCredentialForAuthenticationChallenge 
//- Detect receiver is NSURLAuthenticationChallengeSender
//- Detect if receiver is member variable of NSURLAuthenticationChallenge (abandon this part instead do the next step)
//  - Detect if the second parameter's type is NSURLAuthenticationChallenge, if it is record it as symbol 

//- Detect if that NSURLAuthenticationChallenge variable (parent of receiver) is one of the parameter of the following method 
//  Note: This may be done ahead and then just look it up later
//  – connection:didCancelAuthenticationChallenge:
//  – connection:didReceiveAuthenticationChallenge:
//  – connection:willSendRequestForAuthenticationChallenge:
// .. and if the challenge parameter of the message is also one of the parameters of the above mentioned methods  

// The following seems optional
//- Detect if interface where the current message is contained is in NSURLConnection or NSURLConnectionDelegate


// Sample Source code to detect:
/*

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:
                   (NSURLAuthenticationChallenge *)challenge
{
  [challenge.sender continueWithoutCredentialForAuthenticationChallenge: challenge] ;
}

*/

//// 1st Instance
//
//- Detect if it is class method from NSURLRequest  
//- Detect if it is setAllowsAnyHTTPSCertificate
//- Detect 1st parameter is YES/true/TRUE/or non-zero
//  Optionally check if the value passed to forHost: is not nil
//- Report  


//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecIgnoresValidationErrorsChecker

#include "ClangSACheckers.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

//#define MSEC_DBG
#include "clang/StaticAnalyzer/Core/MSecCommon.h"
#include "llvm/ADT/SmallPtrSet.h"


using namespace clang ;
using namespace ento ;
using namespace msec_cmn ; 
using namespace llvm ;

namespace 
{
  struct IgnoreValidationState: public SMSecState
  {
  public:
    typedef enum { eImplDecl, eMsgCall } eLocationType  ; 
    typedef SmallPtrSet <const IdentifierInfo *, 10> IIPtrSetType ;

  private:
    //eLocationType  m_setIIPtr ; 
    mutable IIPtrSetType   m_setIIPtr ;

    IgnoreValidationState( eSecurityStat eStat, const IdentifierInfo *pInfo )
      : SMSecState( eStat )
      , m_setIIPtr() 
    { 
      m_setIIPtr.clear() ;

      if ( pInfo )
      {
        m_setIIPtr.insert( pInfo ) ;
      }
    } 
  
  public:
    //  static IgnoreValidation
    virtual bool operator==(const IgnoreValidationState &X) const
    {
      return ( m_SecStat == X.m_SecStat ) ; 
    }

    static IgnoreValidationState getSecure( const IdentifierInfo *pInfo )
    {
      return IgnoreValidationState( Secure, pInfo ) ; 
    } 
    
    static IgnoreValidationState getNotSecure( const IdentifierInfo *pInfo ) 
    {
      return IgnoreValidationState( NotSecure, pInfo ) ;
    } 
    
    bool isIdentifierInfoExist( const IdentifierInfo *pInfo ) 
    { 
      return ( std::find( m_setIIPtr.begin()
                 , m_setIIPtr.end(), pInfo ) != m_setIIPtr.end() )  ; 
    } 

    void addIdentifierInfo( const IdentifierInfo *pInfo ) const 
    {
      if ( pInfo )
      {
        m_setIIPtr.insert( pInfo ) ;
      }
    }

    void removeIdentifierInfo( const IdentifierInfo *pInfo ) const
    {
      if ( pInfo )
      {
        m_setIIPtr.erase( pInfo ) ;
      }
    }

    bool isEmptyIdentifierInfoSet() const
    {
      return ( m_setIIPtr.empty() ) ;
    }
  } ;
 
  typedef IgnoreValidationState IgnVS ;
  typedef IdentifierInfo        *&IIPtrRef ;

  //redwud: The main job of this class is to receive call backs for the points
  //        of interest for this checker.
  //        This will mostlikely have one instance. 
  class iOSAppSecIgnoresValidationErrorsChecker 
    : public Checker< 
                      check::PostObjCMessage
                    , check::PostCall
                    , check::DeadSymbols
                    > 
  {
 
  protected:
    mutable IdentifierInfo *m_piiNSURLRequest
      , *m_piiSetAllowsAnyHTTPSCertificate
      , *m_piiForHost
      , *m_piiContWoutCredForAuthChal
      , *m_piiNSURLAuthChalSndr
      , *m_piiChallenge
      , *m_piiConnection   
      , *m_piiDidRxAuthChal 
      , *m_piiNSURLConnectionDelegate
      , *m_piiNSDictionary                         
      , *m_piiDictionaryWithObjectsAndKeys         
      , *m_piiNSMutableDictionary
      , *m_piiSetObject          
      , *m_piiKCFStreamSSLAllowsExpiredCertificates
      , *m_piiKCFStreamSSLAllowsExpiredRoots
      , *m_piiKCFStreamSSLAllowsAnyRoot            
      , *m_piiKCFStreamSSLValidatesCertificateChain
      , *m_piiCFReadStreamSetProperty 
      , *m_piiCFWriteStreamSetProperty 
      ;

    const StringRef m_szReportDesc ;    
    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;
  
    // Is pSymbol one of the previously recorded pSymbol that is marked as not secure 
    bool isInsecureSymbol( const SymbolRef pSymbol, const ProgramStateRef pProgState ) const ; 
  
    bool markSymbolInsecure( SymbolRef pSymbol, const IIPtrRef rpInfo
         , ProgramStateRef pProgState, CheckerContext &C) const ;
  
    void markSymbolsIdentifierSecure( SymbolRef pSymbol
         , const IIPtrRef rpInfo, ProgramStateRef pProgState, CheckerContext &C) const ;

    // NSURLRequest  
    SymbolRef checkNSURLRequestInstance( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const ;  

    // NSURLConnection 
    SymbolRef checkNSURLConnectionInstance( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const ;  

    // NSDictionary insecure setting 
    SymbolRef checkInsecureNSDictionaryInstance( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx
              , IIPtrRef rpInfo ) const ;  

  public:
    //redwud: Default Constructor
    iOSAppSecIgnoresValidationErrorsChecker() ;

    void checkPostObjCMessage( const ObjCMethodCall &M, CheckerContext &C ) const ;
  
    /// A “dead” symbol can never be referenced again along this path 
    /// • Checkers can be notified when symbols die
    //redwud: In simple terms the var got out of scope
    void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const ;

    // Check for CFReadStreamSetProperty
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const ; 
  } ;
  
} // end anonymous namespace

  
/// The state of the checker is a map from tracked stream symbols to their
/// state. Let's store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, IgnVS)

//redwud: Default Constructor
iOSAppSecIgnoresValidationErrorsChecker::iOSAppSecIgnoresValidationErrorsChecker() 
  : m_piiNSURLRequest                         (NULL) 
  , m_piiSetAllowsAnyHTTPSCertificate         (NULL)
  , m_piiForHost                              (NULL)
  , m_piiContWoutCredForAuthChal              (NULL)
  , m_piiNSURLAuthChalSndr                    (NULL)
  , m_piiChallenge                            (NULL) 
  , m_piiConnection                           (NULL) 
  , m_piiDidRxAuthChal                        (NULL)
  , m_piiNSURLConnectionDelegate              (NULL)
  , m_piiNSDictionary                         (NULL)          
  , m_piiDictionaryWithObjectsAndKeys         (NULL) 
  , m_piiNSMutableDictionary                  (NULL)
  , m_piiSetObject                            (NULL) 
  , m_piiKCFStreamSSLAllowsExpiredCertificates(NULL) 
  , m_piiKCFStreamSSLAllowsExpiredRoots       (NULL)
  , m_piiKCFStreamSSLAllowsAnyRoot            (NULL) 
  , m_piiKCFStreamSSLValidatesCertificateChain(NULL)
  , m_piiCFReadStreamSetProperty              (NULL)
  , m_piiCFWriteStreamSetProperty             (NULL)
  , m_szReportDesc                            ("Disabling the certificate checks is a serious mistake. Will cancel security assurances provided by HTTP(TLS protocol).")  
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;
  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType("Ignore certificate validation errors",
                                           "Insufficient Transport Layer Security"));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true );

  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
}


SymbolRef iOSAppSecIgnoresValidationErrorsChecker::checkNSURLRequestInstance( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;

  SymbolRef pRet = NULL ;

  do
  {
    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      break ;
    }

    //NSURLRequest 
    if ( m_piiNSURLRequest != pRxInterface ->getIdentifier() )
    {
      break ;
    } 

    Selector selCurr = M.getSelector() ; 

    //setAllowsAnyHTTPSCertificate: 
    const IdentifierInfo *piiSetAllowAny = selCurr.getIdentifierInfoForSlot(0) ;  

    if ( piiSetAllowAny != m_piiSetAllowsAnyHTTPSCertificate )
    {
       break ;
    }

    //forHost: 
    const IdentifierInfo *piiForHost = selCurr.getIdentifierInfoForSlot(1) ;  

    if ( piiForHost != m_piiForHost )
    {
       break ;
    }

    // Just making sure this is what we are looking for    
    if ( selCurr.getNumArgs() != 2 )
    {
      // Unlikely to be of concerned 
      break ;
    }

    ProgramStateRef pProgState = C.getState() ;

    //Get the value for "allow" parameter (1st)
    const Expr *pAllowExpr = M.getArgExpr(0) ;
    const LocationContext *pLCtx = C.getLocationContext() ; 
    SVal argValAllow = pProgState ->getSVal( pAllowExpr, pLCtx ) ;

    //Is neither of the following values: "YES", "TRUE", "true", "1"   
    if ( argValAllow.isConstant(0) )
    {
      MSEC_DEBUG("redwud:", "Not positive "  << argValAllow ) ;
      // Not of concern
      break ; 
    }

    //Get the value for "host" parameter (2nd)
    // Checking this first because checking the first parameter takes a bit longer    
    const Expr *pForHost = M.getArgExpr(1) ;
    SVal argValForHost = pProgState ->getSVal( pForHost, pLCtx ) ;

    // is Nil?
    if ( argValForHost.isConstant(0) )
    {
      break ;
    }

    StringRef szHost ;

    CMSecCommon::getStrFromExpr( szHost, pForHost ) ;

    if ( szHost.empty() )
    {
      MSEC_DEBUG("redwud:", "host is empty!" ) ;
      break ; 
    }

    SymbolRef pSymNSURLRequest = M.getReceiverSVal().getAsSymbolicExpression() ;

    if ( !pSymNSURLRequest )
    {
      //MSEC_DEBUG("redwud:", "pSymNSURLRequest is NULL" ) ;
      pSymNSURLRequest = CMSecCommon::conjureSymbolRef() ; //do some majick tricks...
    } 

    pRet = pSymNSURLRequest ;

  } while (_PASSING_) ;


  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
  return pRet ;
}


SymbolRef iOSAppSecIgnoresValidationErrorsChecker::checkNSURLConnectionInstance
  ( const ObjCMethodCall &M, CheckerContext &C, ASTContext &Ctx ) const
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;

  SymbolRef pRet = NULL ;
  Selector selCurr = M.getSelector() ; 

  do
  {
    //continueWithoutCredentialForAuthenticationChallenge: 
    const IdentifierInfo *piiContWithout = selCurr.getIdentifierInfoForSlot(0) ;  

    if ( piiContWithout != m_piiContWoutCredForAuthChal )
    {
       break ;
    }

    //
    //NSURLAuthenticatiohnChallengeSender 
    //   

    // continueWithoutCredentialForAuthenticationChallenge
    const ObjCMethodDecl *pMD = M.getDecl();
    
    if ( !pMD )
    {
      //MSEC_DEBUG("redwud: ", "!pMD >>>>> " << piiContWithout ->getName()) ;
      break ;
    }

    const LocationContext *pLCtx = C.getLocationContext() ; 
    const ObjCMethodDecl *pOyaDecl = dyn_cast <ObjCMethodDecl> (pLCtx ->getDecl()) ;

    if ( !pOyaDecl )
    {
      break ;
    }

    // Thes the parent's interface declaration have NSURLConnectionDelegate protocol

    if ( !CMSecCommon::isSupportedProtocol( pOyaDecl, m_piiNSURLConnectionDelegate ) )
    {
      MSEC_DEBUG("redwud: ", "not NSURL Connnection delegate" ) ;
      break ;
    }


    //
    // From the declaration/definition of this method does it belong to NSURLAuthenticationChallengeSender?
    //

    // We want a protocol coz NSURLAuthenticatiohnChallengeSender is a protocol 
    // NSURLAuthenticatiohnChallengeSender 
    const ObjCProtocolDecl *pProt = dyn_cast_or_null< ObjCProtocolDecl >(pMD ->getDeclContext()) ; 
    
    if ( !pProt )
    {
      //MSEC_DEBUG("redwud: ", "!pProt >>>>> " << piiContWithout ->getName()) ;
      break ;
    }

    if ( pProt ->getIdentifier() != m_piiNSURLAuthChalSndr )
    {
       break ;
    }

    // Adding extra checking to make sure this is the right method that we are confirming. 
    if ( selCurr.getNumArgs() != 1 )
    {
      // Unlikely to be of concerned 
      break ;
    }

    ProgramStateRef pProgState = C.getState() ;

    if ( !pLCtx )
    {
      break ;
    }
    
    //
    //Get the value for "challenge" parameter (1st)
    //

    const Expr *pExprChallenge = M.getArgExpr(0) ;
    SVal argValChallenge = pProgState ->getSVal( pExprChallenge, pLCtx ) ;

    //Is it nil?
    if ( argValChallenge.isConstant(0) )
    {
      // Not of concern
      break ; 
    }

    // challenge
    const ParmVarDecl *pParmVarDecl = M.parameters()[0] ;

    //This should be like NSURLAuthenticationChallenge but for now we just need to know
    //this is challenge and with the assumption that this is of the aforementioned type.
    if ( (!pParmVarDecl) || (pParmVarDecl ->getIdentifier() != m_piiChallenge) )
    {
      break ;
    }


    Selector selOya = pOyaDecl ->getSelector() ;

    if ( selOya.getNumArgs() != 2 )
    {
      break ;
    }

    //connection:
    if ( selOya.getIdentifierInfoForSlot( 0 ) != m_piiConnection )
    {
      break ;
    }
  
    //didReceiveAuthenticationChallenge:
    if ( selOya.getIdentifierInfoForSlot( 1 ) != m_piiDidRxAuthChal )
    {
      break ;
    }

    //
    // Confirm if the challenge being passed to this call is the same challenge from the  parent decl
    //

    ParmVarDecl *pOyaChalParm = pOyaDecl ->parameters()[1] ;

    if ( !pOyaChalParm )
    {
      break ;
    }
    
    const DeclRefExpr *pKoChalDeclRef = dyn_cast <DeclRefExpr> ( *(pExprChallenge -> child_begin()) ) ;

    if ( !pKoChalDeclRef )
    {
      break ;
    }

    const ParmVarDecl *pKoChalParm = dyn_cast <ParmVarDecl> (pKoChalDeclRef ->getDecl()) ;
    
    if ( !pKoChalParm )
    {
      break ;
    }
    
    if ( pKoChalParm != pOyaChalParm )
    {
      //MSEC_DEBUG("redwud:", "challenge from parent method  is not passed to child or current method call " ) ;
      break ;
    }

    //
    // Check where the sender is contained, if it is from the the challenge received from the parent method
    //

    // Get the 2nd grand child's grand child
    const Stmt *pRxKoStmt = *( M.getOriginExpr() -> child_begin() ) ;

    if ( !pRxKoStmt )
    {
      break ;
    }

    const Stmt *pRxGrandKoStmt = *( ++(pRxKoStmt ->child_begin()) ) ; 

    if ( !pRxGrandKoStmt )
    {
      break ;
    }
    
    // Recycling here, not typical for me but for now I will abstain
    const OpaqueValueExpr *pOpaqueExpr = dyn_cast <OpaqueValueExpr> (pRxGrandKoStmt) ;

    if ( !pOpaqueExpr )
    {
      break ;
    }

    pRxKoStmt = pOpaqueExpr -> getSourceExpr() ;

    if ( !pRxKoStmt )
    {
      break ;
    }

    const DeclRefExpr *pRxChalDeclRef = dyn_cast <DeclRefExpr> ( *(pRxKoStmt -> child_begin()) ) ;   
                                                                                                        
    if ( !pRxChalDeclRef )
    {
      break ;
    }
                                                                                                        
    const ParmVarDecl *pRxChalParm = dyn_cast <ParmVarDecl> (pRxChalDeclRef ->getDecl()) ;
    
    // Not a parameter, then it must have been a local variable
    if ( !pRxChalParm )
    {
      //MSEC_DEBUG("redwud:", "challenge from parent is not the receiving challenge " ) ;
      break ;
    }

    // The receiving challenger is not the one from the parent's challenger 
    if ( pRxChalParm != pKoChalParm )
    {
      break ; 
    }

    pRet = argValChallenge.getAsSymbol() ; 

  } while (_PASSING_) ;

  MSEC_DEBUG_FUNC("redwud:","EXIT") ;

  return pRet ; 
} 


//FIXME: Support multiple items in one call, it would not be a good idea to run build-analyze a lot of times
//       in order to fix one line of code with multiple warnings.

// NSDictionary insecure setting 
SymbolRef iOSAppSecIgnoresValidationErrorsChecker::checkInsecureNSDictionaryInstance( const ObjCMethodCall &M
    , CheckerContext &C, ASTContext &Ctx, IIPtrRef rpInfo ) const
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;

  SymbolRef pRet = NULL ;
  Selector selCurr = M.getSelector() ; 

  do
  {
    //continueWithoutCredentialForAuthenticationChallenge: && setObject: 
    const IdentifierInfo *piiDicWithObjKs = selCurr.getIdentifierInfoForSlot(0) ;  

    //Not the target messages
    if ( (piiDicWithObjKs != m_piiDictionaryWithObjectsAndKeys) && 
         (piiDicWithObjKs != m_piiSetObject) )
    {
       break ;
    }

    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      break ;
    }

    //NSMutableDictionary && NSDictionary
    const IdentifierInfo *pRxIdentifier = pRxInterface ->getIdentifier() ;

    //Not the target receivers
    if ( (pRxIdentifier != m_piiNSDictionary) &&
         (pRxIdentifier != m_piiNSMutableDictionary) )
    {
      break ;
    } 
    
    unsigned   iNumArgs = M.getNumArgs() ; 
    SymbolRef  pSymToCheck = NULL ; 

    //
    // Get the symbol ahead, there is no point of checking if you can't report it
    //

    // By default this is for setObject:
    SymbolRef pWorkSymbol = M.getReceiverSVal().getAsSymbol() ;

    // This means we are dealing with dictionaryWithObjectsAndKeys:
    if ( !pWorkSymbol )
    {
      pWorkSymbol = M.getReturnValue().getAsSymbol() ;
    }

    if ( !pWorkSymbol )
    {
      MSEC_DEBUG("redwud:","!pWorkSymbol again! >>>>> " << piiDicWithObjKs ->getName() ) ;
      break ;
    }
    //NOTE: This construct opens to the possibility that
    //      there might be more entries of concern, not only these ones.
    struct 
    {
      IdentifierInfo *pII ;
      bool            bInsecureVal ;
    } aInsecurePairs[] = 
    { 
        { m_piiKCFStreamSSLAllowsExpiredCertificates , true  }
      , { m_piiKCFStreamSSLAllowsExpiredRoots        , true  }
      , { m_piiKCFStreamSSLAllowsAnyRoot             , true  }
      , { m_piiKCFStreamSSLValidatesCertificateChain , false }   
    }, *pInsecPair = NULL ;

    // This is not necessarily be contained in a variable because it is a macro call
    const unsigned iInsecPairCount = _countof( aInsecurePairs ) ;

    // Go through each parameter unless find some sensitive info in one of them
    for ( unsigned iCtr = 0; (iCtr < iNumArgs) && (!pSymToCheck); iCtr++ )
    {
      const Expr *pExpr = M.getArgExpr( iCtr ) ;
      pInsecPair = NULL ;

      for ( unsigned iPairs = 0; (iPairs < iInsecPairCount) && (!pSymToCheck); iPairs++ )
      {
        if ( CMSecCommon::findIdentifierInStmt( pExpr, aInsecurePairs[ iPairs ].pII ) )
        {
          pInsecPair = &aInsecurePairs[ iPairs ] ;
          break ;
        }
      }

      // Found a property to be concerned about
      if ( !pInsecPair ) 
      {
        continue ;
      }

      const Expr *pPrevExpr = M.getArgExpr( iCtr - 1 ) ;

      // Get the object of the key (usually the previous parameter)
      if ( !pPrevExpr )
      {
        continue ;
      }
      
      bool bValue = false ;

      if ( !CMSecCommon::getInnerBool( pPrevExpr, bValue ) )
      {
        //MSEC_DEBUG( "\nredwud:", "Inner found:" << bValue  << "\n" ) ;
        continue ; 
      }

      //Spotted the identifier but sets secure value
      if ( pInsecPair -> bInsecureVal != bValue )
      {
        ProgramStateRef  pProgState = C.getState() ;
       
        markSymbolsIdentifierSecure( pWorkSymbol, pInsecPair ->pII, pProgState, C ) ;
        continue ;
      }

      // Get the symbolic value corresponding to the target parameter.
      pSymToCheck = pWorkSymbol ; 
    } // for each parameter

    if ( !pSymToCheck )
    {
      break ;
    }

    pRet = pSymToCheck ;
    rpInfo = pInsecPair -> pII ;
    
    //MSEC_DEBUG( "\nredwud:", "<<<<< this should show up!!!" << (void *)rpInfo <<  " \n" ) ;
  } while (_PASSING_) ;

  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
  return pRet ;
}

/// Process two instances of this vulnerability 
void iOSAppSecIgnoresValidationErrorsChecker::checkPostObjCMessage 
  (const ObjCMethodCall &M, CheckerContext &C) const
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;
  SymbolRef pSymToCheck = NULL ; 

  do
  {
    ASTContext &Ctx = C.getASTContext() ;

    initIdentifierInfo( Ctx ) ;

    if ( !m_pInsecureInstBugType )
    {
       MSEC_DEBUG("redwud:","!m_pInsecureInstBugType") ;
       break ;
    }

    ProgramStateRef pProgState = C.getState() ;

    pSymToCheck = checkNSURLRequestInstance( M, C, Ctx ) ;

    if ( pSymToCheck  )
    {
      //Report this instance
      CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
        , *m_pInsecureInstBugType, m_szReportDesc ) ;

      //FIXME: Test this break
      break ;
    }  
   
    pSymToCheck = checkNSURLConnectionInstance( M, C, Ctx ) ;

    if ( pSymToCheck )
    {
      //Report this instanc too!
      CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
        , *m_pInsecureInstBugType, m_szReportDesc ) ;

      //FIXME: Test this break
      break ;
    }  

    IdentifierInfo *pII = NULL ;

    pSymToCheck = checkInsecureNSDictionaryInstance( M, C, Ctx, pII ) ;

    if ( !pSymToCheck || !pII )
    {
       break ;
    }  

    //This time hold it for CFReadStreamSetProperty or CFWriteStreamSetProperty call 
    if ( !markSymbolInsecure( pSymToCheck, pII, pProgState, C ) )
    {
      MSEC_DEBUG("redwud:","!markSymbolInsecure") ;
    }

  } while (_PASSING_) ;

  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
}


//TODO: Add extra state here, whether impl_decl, msg_cal 
bool iOSAppSecIgnoresValidationErrorsChecker::isInsecureSymbol( const SymbolRef pSymbol, 
       const ProgramStateRef pProgState ) const
{
  bool bRet = false ;

  do
  {
    if ( !pSymbol || !pProgState )
    {
      MSEC_DEBUG("redwud:","!isInsecure sym " << (void *)pSymbol << " state "  ) ;
      break ;
    }
    
    const IgnVS *pIgnoreValState = pProgState ->get <StreamMap> ( pSymbol ) ; 
    
    if ( !pIgnoreValState )
    {
      MSEC_DEBUG("redwud:","!pIgnoreValStat esym " << (void *)pIgnoreValState ) ;
      break ;
    }
      
    bRet = true ;

  } while( _PASSING_ ) ;

  return bRet ;
} 

// returns true if successful mark of symbol, otherwise false.
bool iOSAppSecIgnoresValidationErrorsChecker::markSymbolInsecure( SymbolRef pSymbol, const IIPtrRef rpInfo
       , ProgramStateRef pProgState, CheckerContext &C ) const
{
  bool bRet = false ;
 
  do
  {
    if ( !pSymbol || !pProgState )
    {
      //MSEC_DEBUG("redwud:","!markSymbolInsecure sym " << (void *)pSymbol << " state "  ) ;
      break ;
    }

    const IgnVS *pIgnoreValState = pProgState ->get <StreamMap> ( pSymbol ) ; 
 
    // Check if already existing 
    if ( pIgnoreValState )
    {
      pIgnoreValState -> addIdentifierInfo( rpInfo ) ;
    }
    else
    {
      //Create the state 
      pProgState = pProgState ->set <StreamMap> ( pSymbol, IgnVS::getNotSecure(rpInfo) ) ; 
    }               
    
    if ( !pProgState )
    {
      //MSEC_DEBUG("redwud:","!pProgState >>>>> ") ;
      break ;
    }
    
    C.addTransition( pProgState ) ;  

    bRet = true ;
  } while( _PASSING_ ) ;

  return bRet ;
}

//TODO: Decide whether "remove" is more appropriate than mark since it is the actual internal operation 
void iOSAppSecIgnoresValidationErrorsChecker::markSymbolsIdentifierSecure( SymbolRef pSymbol
       , const IIPtrRef rpInfo, ProgramStateRef pProgState, CheckerContext &C) const
{
  do
  {
    if ( !pSymbol || !pProgState )
    {
      //MSEC_DEBUG("redwud:","!markSymbolsIdentifierSecure sym " << (void *)pSymbol << " state "  ) ;
      break ;
    }

    const IgnVS *pIgnoreValState = pProgState ->get <StreamMap> ( pSymbol ) ; 
 
    // Check if already existing 
    if ( !pIgnoreValState )
    {
      break ;
    }

    pIgnoreValState ->removeIdentifierInfo( rpInfo ) ;

    if ( pIgnoreValState ->isEmptyIdentifierInfoSet() )
    {
      pProgState = pProgState -> remove<StreamMap>( pSymbol ) ;
      C.addTransition( pProgState ) ;
    }

  } while( _PASSING_ ) ;
}

void iOSAppSecIgnoresValidationErrorsChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const 
{
  MSEC_DEBUG_FUNC("redwud:","ENTER") ;

  do
  {
    // No point if you can't report it in the end
    if ( !m_pInsecureInstBugType )
    {
      MSEC_DEBUG( "redwud: ", "!m_pInsecureInstBugType" ) ;
      break ;
    }

    initIdentifierInfo( C.getASTContext() ) ;

    //redwud: Obviously it is what it is
    if ( !Call.isGlobalCFunction() )
    {
      break ;
    }

    const IdentifierInfo *pCalleeIdent = Call.getCalleeIdentifier() ; 

    //We do away with array because it's only two of them and it
    //will break the while..passing pattern  
    if ( (pCalleeIdent != m_piiCFReadStreamSetProperty) &&
         (pCalleeIdent != m_piiCFWriteStreamSetProperty) )
    {    
      break ;
    }
    
    // Get the symbolic value corresponding to the "propertyValue" parameter.
    SymbolRef pSymToCheck = Call.getArgSVal( 2 ).getAsSymbol() ;

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
 
    //Report this instance
    CMSecCommon::reportInsecureInstance( pSymToCheck, C, C.addTransition( pProgState )
      , *m_pInsecureInstBugType, m_szReportDesc ) ;
  

  } while ( _PASSING_ ) ;

  MSEC_DEBUG_FUNC("redwud:","EXIT") ;
}

void iOSAppSecIgnoresValidationErrorsChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                           CheckerContext &C) const
{
  ProgramStateRef pProgState = C.getState() ;
  StreamMapTy TrackedStreams = pProgState -> get <StreamMap>() ;
 
  for (StreamMapTy::iterator pItem = TrackedStreams.begin(),
                             pEndItem = TrackedStreams.end(); pItem != pEndItem; ++pItem) 
  {
    SymbolRef pSymbol = pItem ->first ;
    
    // Remove the dead symbol from the streams map.
    if ( SymReaper.isDead( pSymbol ) )
    {
      pProgState = pProgState -> remove <StreamMap> ( pSymbol ) ;
    }
  }

  C.addTransition( pProgState ) ;
}


//NOTE: This method is made to be separated because ASTContext is not available during instatiation
void iOSAppSecIgnoresValidationErrorsChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
  do
  {
    //redwud: prevent the following to from gettting reinitialized
    if ( m_piiNSURLRequest )
    {
      break ;      
    }

    MSEC_DEBUG_FUNC("redwud:","ENTER") ;

    m_piiNSURLRequest                          = &Ctx.Idents.get("NSURLRequest") ;
    m_piiSetAllowsAnyHTTPSCertificate          = &Ctx.Idents.get("setAllowsAnyHTTPSCertificate") ;
    m_piiForHost                               = &Ctx.Idents.get("forHost") ;
    m_piiContWoutCredForAuthChal               = &Ctx.Idents.get("continueWithoutCredentialForAuthenticationChallenge") ;     
    m_piiNSURLAuthChalSndr                     = &Ctx.Idents.get("NSURLAuthenticationChallengeSender") ;
    m_piiChallenge                             = &Ctx.Idents.get("challenge") ;
    m_piiConnection                            = &Ctx.Idents.get("connection") ; 
    m_piiDidRxAuthChal                         = &Ctx.Idents.get("didReceiveAuthenticationChallenge") ;
    m_piiNSURLConnectionDelegate               = &Ctx.Idents.get("NSURLConnectionDelegate") ;
    m_piiNSDictionary                          = &Ctx.Idents.get("NSDictionary") ; 
    m_piiDictionaryWithObjectsAndKeys          = &Ctx.Idents.get("dictionaryWithObjectsAndKeys") ;
    m_piiNSMutableDictionary                   = &Ctx.Idents.get("NSMutableDictionary") ; 
    m_piiSetObject                             = &Ctx.Idents.get("setObject") ;
    m_piiKCFStreamSSLAllowsExpiredCertificates = &Ctx.Idents.get("kCFStreamSSLAllowsExpiredCertificates") ;
    m_piiKCFStreamSSLAllowsExpiredRoots        = &Ctx.Idents.get("kCFStreamSSLAllowsExpiredRoots") ;
    m_piiKCFStreamSSLAllowsAnyRoot             = &Ctx.Idents.get("kCFStreamSSLAllowsAnyRoot") ;
    m_piiKCFStreamSSLValidatesCertificateChain = &Ctx.Idents.get("kCFStreamSSLValidatesCertificateChain") ;
    m_piiCFReadStreamSetProperty               = &Ctx.Idents.get("CFReadStreamSetProperty") ;
    m_piiCFWriteStreamSetProperty              = &Ctx.Idents.get("CFWriteStreamSetProperty") ;

    MSEC_DEBUG_FUNC("redwud:","EXIT") ;

  } while (_PASSING_) ;

}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecIgnoresValidationErrorsChecker(CheckerManager &mgr) 
{
  mgr.registerChecker< iOSAppSecIgnoresValidationErrorsChecker >();
}

