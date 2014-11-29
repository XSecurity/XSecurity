//===-- iOSAppSecSQLInjectionChecker.cpp -----------------------------------------*- C++ -*--//
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

 - (IBAction) sample_SQLInjection: (id)sender
 {
     // Search the database for articles matching the search string.
     NSString *dbPath = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"articles.sqlite"];
     NSString *szSearchFieldText = @"sample search" ;
     
     sqlite3 *db;
     const char *path = [dbPath UTF8String];
     
     if (sqlite3_open(path, &db) != SQLITE_OK) 
     {
         NSLog( @"displayAlertWithTitle: Snap! message:Error opening articles database.") ;
         return;
     }
     
     NSString *searchString = [szSearchFieldText length] > 0 ? [NSString stringWithFormat:@"%@%@%@", @"%", szSearchFieldText, @"%"] : @"%";
     NSString *query = [NSString stringWithFormat:@"SELECT title FROM article WHERE title LIKE '%@' AND premium=0", searchString];
     
     sqlite3_stmt *stmt;
     sqlite3_prepare_v2(db, [query UTF8String], -1, &stmt, nil);
     
     NSMutableArray *articleTitles = [[NSMutableArray alloc] init];
     
     while (sqlite3_step(stmt) == SQLITE_ROW)
     {
         NSString *title = [[NSString alloc] initWithUTF8String:(char *)sqlite3_column_text(stmt, 0)];
         [articleTitles addObject:title];
     }
     
     sqlite3_finalize(stmt);
     sqlite3_close(db);
     
     // Create the articles (table) controller.
     CViewController *articlesController = [[CViewController alloc] initWithNibName:@"SQLInjectionArticlesViewController" bundle: nil articleTitles: articleTitles];
     
     // Pass the selected object to the new view controller.
     [self.navigationController pushViewController:articlesController animated:YES];
 }

*/

// Implementation Notes:
// - Mark all string symbols which is using format methods if there is a format specifier included 
//   in the format string itself
// - If the previously marked string symbols generate further symbols then mark it too
// - Mark the statement symbols used in sqlite3_prepare_v2() when using the previously marked symbol
// - If marked statement symbol is used in sqlite3_bind_text() then do nothing
// - When sqlite3_step() is called using the previously marked statement symbol then issue a warning

// List of formatting methods for NSString and NSMutable string:
// NSString
// + stringWithFormat:
// + localizedStringWithFormat:
// – initWithFormat:
// – stringByAppendingFormat:
// 
// 
// NSMutableString
// – appendformat:

//===----------------------------------------------------------------------===//
//-Xanalyzer -analyzer-checker=alpha.osx.cocoa.iOSAppSecSQLInjectionChecker

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
  typedef SMSecState SQLInjectState ; 

  //redwud: The main job of this class is to receive call backs for the points
  //        of interest for this checker.
  class iOSAppSecSQLInjectionChecker 
    : public Checker< 
                      check::PostObjCMessage 
                    , check::PostCall
                    , check::DeadSymbols
                    > 
  {
 
  protected:
    mutable IdentifierInfo *m_piiNSString
                         , *m_piiNSMutableString
                         , *m_piiStringWithFormat
                         , *m_piiLocalizedStringWithFormat
                         , *m_piiInitWithFormat
                         , *m_piiStringByAppendingFormat
                         , *m_piiAppendformat
                         , *m_piiSqlite3_prepare     
                         , *m_piiSqlite3_prepare_v2  
                         , *m_piiSqlite3_prepare16   
                         , *m_piiSqlite3_prepare16_v2
                         , *m_piiSqlite3_bind_text
                         , *m_piiSqlite3_step
                         ; 

    const StringRef       m_szReportDesc ;    
    OwningPtr < BugType > m_pInsecureInstBugType ;
  
    void initIdentifierInfo(ASTContext &Ctx) const;
  
    // Is pSymbol one of the previously recorded pSymbol that is marked as not secure 
    bool isInsecureSymbol( const SymbolRef pSymbol, const ProgramStateRef pProgState ) const ; 
  
    ProgramStateRef markSymbolInsecure( const SymbolRef pSymbol, ProgramStateRef pProgState, CheckerContext &C ) const ;
    
  public:
    //redwud: Default Constructor
    iOSAppSecSQLInjectionChecker() ;

    // ObjC Message checker most for NSString method calls
    void checkPostObjCMessage(const ObjCMethodCall &M, CheckerContext &C) const ;

    // Returns a symbol if it has been processed, otherwise NULL 
    SymbolRef checkSQLPrepareStatement( const CallEvent &revCall, CheckerContext &C, ASTContext &Ctx ) const ;  

    //SymbolRef checkSQLBindText( const CallEvent &revCall, CheckerContext &C, ASTContext &Ctx ) const ;  

    //FIXME: Add support for sqlite3_exec()
    SymbolRef checkSQLStep( const CallEvent &revCall, CheckerContext &C, ASTContext &Ctx ) const ; 
    // Process  
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    
    /// A “dead” symbol can never be referenced again along this path 
    /// • Checkers can be notified when symbols die
    //redwud: In simple terms the var got out of scope
    void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;
  };
  
} // end anonymous namespace
  
/// The state of the checker is a map from tracked stream symbols to their
/// state. Let's store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, SQLInjectState)


//redwud: Default Constructor
iOSAppSecSQLInjectionChecker::iOSAppSecSQLInjectionChecker() 
  : m_piiNSString                 (NULL)
  , m_piiNSMutableString          (NULL)
  , m_piiStringWithFormat         (NULL)
  , m_piiLocalizedStringWithFormat(NULL)
  , m_piiInitWithFormat           (NULL)
  , m_piiStringByAppendingFormat  (NULL)
  , m_piiAppendformat             (NULL)
  , m_piiSqlite3_prepare          (NULL)
  , m_piiSqlite3_prepare_v2       (NULL)
  , m_piiSqlite3_prepare16        (NULL)
  , m_piiSqlite3_prepare16_v2     (NULL)
  , m_piiSqlite3_bind_text        (NULL)
  , m_piiSqlite3_step             (NULL)
  , m_szReportDesc                ("This portion of the code is vulnerable to SQL Injection.")  
{
  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;

  // Initialize the bug type, no sinks in this vulnerability.

  m_pInsecureInstBugType.reset(new BugType( "SQL Injection",
                                            "Client Side Injection"));

  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  m_pInsecureInstBugType ->setSuppressOnSink( true );

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
}

//FIXME: Support c-string style formatting as well, because NSString variants are not the only
//       possible way to introduce SQL Injection vulnerability

//FIXME: Too, there is an extra call to stringWithFormat which seems not caused by extra call to addTransition()
//       go figure it out.

/// Process call to format strings 
void iOSAppSecSQLInjectionChecker::checkPostObjCMessage(const ObjCMethodCall &M, CheckerContext &C) const
{
  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;

  do
  {
    ProgramStateRef pProgState = C.getState() ;

    if ( !pProgState )
    {
      MSEC_DEBUG( "redwud: ", "Unlikely but true, !pProgStateFinish" ) ; 
      break ;
    }

    //
    // Check if previously marked as insecure symbol breeds more insecure symbols
    //
    SymbolRef pRxSymbol = M.getReceiverSVal().getAsSymbol() ;

    if ( isInsecureSymbol( pRxSymbol, pProgState ) )
    {
      //MSEC_DEBUG( "redwud: ", "$$$$$$$$$ Previously insecure receiver: " << (void *)pRxSymbol ) ; 

      QualType qt = M.getResultType() ;
      std::string szType = QualType::getAsString( qt.split() ) ;

      // Non-string related type is not of concern
      // Old school negation, meaning neither of the following
      if ( !(szType == "const char *" || szType == "NSString" || szType == "NSMutableString") )
      {
        break ;
      }

      //MSEC_DEBUG( "redwud: ", "$$$$$$$$$ split type: " << szType ) ; 

      if ( markSymbolInsecure( M.getReturnValue().getAsSymbol(), pProgState, C ) )
      {
        // MSEC_DEBUG( "redwud: ", "$$$$$$$$$ Marked as insecure =  " << (void *)M.getReturnValue().getAsSymbol() ) ; 
        break ;
      }
    }
    
    const ObjCInterfaceDecl *pRxInterface = M.getReceiverInterface() ;
    
    if ( !pRxInterface )
    {
      break ;
    }

    ASTContext &Ctx = C.getASTContext() ;
    Selector selCurr = M.getSelector() ; 

    initIdentifierInfo( Ctx ) ;

    IdentifierInfo *pRxIdentifier = pRxInterface ->getIdentifier() ; 

    //NSString and NSMutableString
    if ( (pRxIdentifier != m_piiNSString) && (pRxIdentifier != m_piiNSMutableString) )
    {
      //MSEC_DEBUG( "redwud: ", "!NSString and !NSMutableString <<< " << pRxIdentifier ->getName() ) ; 
      break ;
    } 

    //Format identifier 
    IdentifierInfo *piiFormat = selCurr.getIdentifierInfoForSlot(0) ;  

    //Not one of the format messages
    if (  (piiFormat != m_piiStringWithFormat) 
       && (piiFormat != m_piiLocalizedStringWithFormat) 
       && (piiFormat != m_piiInitWithFormat           ) 
       && (piiFormat != m_piiStringByAppendingFormat  ) 
       && (piiFormat != m_piiAppendformat             )  ) 
    {
       //MSEC_DEBUG( "redwud: ", "!Format string  <<< " << piiFormat ->getName() ) ; 
       break ;
    }
    
    unsigned iParams = M.getNumArgs() ;

    // One and below it means it is equal to initialization, rather than formatting
    if ( iParams < 2 )
    {
      MSEC_DEBUG( "redwud: ", "Too few parameters =  " << (void *)M.getReturnValue().getAsSymbol() ) ; 
      break ;
    }
   
    const Expr *pFormatExpr = M.getArgExpr(0) ;

    if ( !pFormatExpr )
    {
      //MSEC_DEBUG( "redwud: ", "!pFormatExpr <<< ") ; 
      break ;
    }

    StringRef szFormat ;

    CMSecCommon::getStrFromExpr( szFormat, pFormatExpr ) ;

    if ( szFormat.empty() )
    {
      MSEC_DEBUG( "redwud: ", "szFormat.empty()  <<< ") ; 
      break ;
    }

    // Doesn't have format specifier?
    if ( szFormat.find('%') == StringRef::npos )
    {
      MSEC_DEBUG( "redwud: ", "% !present <<< ") ; 
      break ;
    }

    //
    // Check if the parameters for the formatter is constant string
    //
   
    StringRef szParams ;
    bool bOneEmpty = false ;
    
    //MSEC_DEBUG( "redwud: ", " parmeter " << iParams << "\n" ) ; 
    const Expr *pExpr = M.getOriginExpr() ;

    for ( unsigned iCtr = 1; iCtr < iParams; iCtr++ )
    {
      const Expr *pParamExpr = CMSecCommon::getParamExpr( pExpr, iCtr ) ;
      
      if ( !pParamExpr )
      {
        MSEC_DEBUG( "redwud: ", "!pParamExpr " << iCtr << "\n" ) ;
        continue ;
      }
      
      CMSecCommon::getStrFromExpr( szParams, pParamExpr ) ;
      
      if ( szParams.empty() )
      {
        bOneEmpty = true ;
        MSEC_DEBUG( "redwud: ", "Empty String: \n" ) ;
        MSEC_DEBUG( "redwud: ", "Dumping parmeter " << iCtr << "\n" ) ; 
        
#ifdef MSEC_DEBUG
        pParamExpr ->dumpColor() ;
#endif
        continue ;
      }
      // else
      // {
      //   MSEC_DEBUG( "redwud: ", "String: " << szParams << "\n" ) ;
      // }
    }

    //FIXME: This is a temporary fix for checking if the passed string is a constant or not.
    if ( !bOneEmpty )
    {
      break ;
    }

    //Use the receiver SVal's symbol
    //Is class method?
    if ( !pRxSymbol )
    {
      // Get the return value of the class method
      pRxSymbol = M.getReturnValue().getAsSymbol() ;
    }

    if ( markSymbolInsecure( pRxSymbol, pProgState, C ) )
    {
      //MSEC_DEBUG( "redwud: ", "$$$$$$$$$ Marked as insecure =  " << (void *)M.getReturnValue().getAsSymbol() ) ; 
      break ;
    }
  } while (_PASSING_) ;

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
}

//Interfaces:
// SQLITE_API int sqlite3_prepare(
//    sqlite3 *db,            /* Database handle */
//    const char *zSql,       /* SQL statement, UTF-8 encoded */
//    int nByte,              /* Maximum length of zSql in bytes. */
//    sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
//    const char **pzTail     /* OUT: Pointer to unused portion of zSql */
// );
// 
// SQLITE_API int sqlite3_prepare_v2(
//    sqlite3 *db,            /* Database handle */
//    const char *zSql,       /* SQL statement, UTF-8 encoded */
//    int nByte,              /* Maximum length of zSql in bytes. */
//    sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
//    const char **pzTail     /* OUT: Pointer to unused portion of zSql */
// );
// 
// SQLITE_API int sqlite3_prepare16(
//    sqlite3 *db,            /* Database handle */
//    const char *zSql,       /* SQL statement, UTF-8 encoded */
//    int nByte,              /* Maximum length of zSql in bytes. */
//    sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
//    const char **pzTail     /* OUT: Pointer to unused portion of zSql */
// );
// 
// SQLITE_API int sqlite3_prepare16_v2(
//    sqlite3 *db,            /* Database handle */
//    const char *zSql,       /* SQL statement, UTF-8 encoded */
//    int nByte,              /* Maximum length of zSql in bytes. */
//    sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
//    const char **pzTail     /* OUT: Pointer to unused portion of zSql */
// );
// 

SymbolRef iOSAppSecSQLInjectionChecker::checkSQLPrepareStatement( const CallEvent &revCall, CheckerContext &C, ASTContext &Ctx ) const
{
  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;
  SymbolRef pRet = NULL ;

  do
  {
    const IdentifierInfo *pCalleeIdent = revCall.getCalleeIdentifier() ; 

    if (  (pCalleeIdent != m_piiSqlite3_prepare     )
       && (pCalleeIdent != m_piiSqlite3_prepare_v2  )
       && (pCalleeIdent != m_piiSqlite3_prepare16   )
       && (pCalleeIdent != m_piiSqlite3_prepare16_v2)  )
    {
      //MSEC_DEBUG( "redwud: ", "!Prepare statements " << pCalleeIdent ->getName() ) ; 
      break ;
    }
    
    ProgramStateRef pProgState = C.getState() ;

    //No need to check if pProgState is NULL or not  because of the call to 
    //isInsecureSymbol which does the same checking

    //
    // Check the 2nd parameter if it is one of the registerd symbols
    //
    SymbolRef pSymQuery = revCall.getArgSVal(1).getAsSymbol() ;

    if ( !isInsecureSymbol( pSymQuery, pProgState ) )
    {
      //MSEC_DEBUG( "redwud: ", "----- pSymQuery is Secure!!!" << pSymQuery << "<<< ") ; 
      break ;
    }

    // MSEC_DEBUG( "redwud: ", "----- Insecure pSymQuery " << (void *)pSymQuery << "<<< ") ; 
    //
    // Mark 4th parameter's symbol as insecure
    //
    SVal          fourthVal = revCall.getArgSVal(3) ;
    SymbolRef pSymStatement = fourthVal.getAsSymbol() ;

    // If symbol is not present yet conjure one to use one.
    if ( !pSymStatement )
    {
      SValBuilder &rsvBldr = C.getSValBuilder() ;
      const Expr *pSqlStmtExpr = revCall.getArgExpr(3) ;
      const LocationContext *pLCtx = C.getLocationContext() ; 
 
      //FIXME: Figure out the neessary value of the last paramter here
      SymbolRef pConjured = rsvBldr.conjureSymbol( pSqlStmtExpr, pLCtx, 1 ) ;
 
      if ( !pConjured )
      {
        break ;
      }

      SVal svalLoc  = rsvBldr.makeLoc( pConjured ) ;
      pProgState    = pProgState ->bindLoc( fourthVal, svalLoc ) ;  
      pSymStatement = pConjured ;
    }

    if ( !markSymbolInsecure( pSymStatement, pProgState, C ) )
    {
      break ;
    }
    //MSEC_DEBUG( "redwud: ", "$$$$$$$$$ Marked as insecure =  " << (void *)pSymStatement ) ; 
    pRet = pSymStatement ;

  } while ( _PASSING_ ) ;

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
  return pRet ;
}

//Note: It seems that a call sqlite3_bind_text() alone will not guarantee that SQL injection is not possible.
//      How about the scenario when a call to format string function/method has already been done prior to
//      this call.
//SymbolRef iOSAppSecSQLInjectionChecker::checkSQLBindText( const CallEvent &revCall, CheckerContext &C, ASTContext &Ctx ) const 
//{
//  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;
//  SymbolRef pRet = NULL ;
//
//  do
//  {
//    
//  
//  } while ( _PASSING_ ) ;
//
//  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
//  return pRet ;
//}

SymbolRef iOSAppSecSQLInjectionChecker::checkSQLStep( const CallEvent &revCall, CheckerContext &C, ASTContext &Ctx ) const 
{
  MSEC_DEBUG_FUNC("redwud: ","ENTER") ;
  SymbolRef pRet = NULL ;

  do
  {
    const IdentifierInfo *pCalleeIdent = revCall.getCalleeIdentifier() ; 

    if ( pCalleeIdent != m_piiSqlite3_step )
    {
      break ;
    }
 
    //
    // Check the 1st parameter if it is one of the registerd symbols
    //
    const SymbolRef pSymStatement = revCall.getArgSVal(0).getAsSymbol() ;
    ProgramStateRef pProgState    = C.getState() ;

    if ( !isInsecureSymbol( pSymStatement, pProgState ) )
    {
      break ;
    }
 
    //MSEC_DEBUG( "redwud: ", "!!!!!!!! symref this is NOT SAFEEEEEEEE !!!!!!" << (void *)pSymStatement ) ; 
    pRet = pSymStatement ;
  
  } while ( _PASSING_ ) ;

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
  return pRet ;
}

// Checking for SecItemAdd and SecItemUpdate, no particular reason for assigning it to PostCall
void iOSAppSecSQLInjectionChecker::checkPostCall(const CallEvent &revCall,
                                        CheckerContext &C) const 
{
  MSEC_DEBUG_FUNC("\n\nredwud: ","ENTER") ;

  do
  {
    initIdentifierInfo( C.getASTContext() ) ;

    //redwud: Obviously it is what it is
    if ( !revCall.isGlobalCFunction() )
    {
      break ;
    }
   
    ASTContext &Ctx        = C.getASTContext() ;
    SymbolRef pSymbolFound = checkSQLPrepareStatement( revCall, C, Ctx ) ;

    // Don't continue because record to the program state has been made
    if ( pSymbolFound )
    {
      break ;
    }

//Note: It seems that a call sqlite3_bind_text() alone will not guarantee that SQL injection is not possible.
//      How about the scenario when a call to format string function/method has already been done prior to
//      this call.
//    pSymbolFound = checkSQLBindText( revCall, C, Ctx ) ;
//
//    // Same here, don't continue because record to the program state has been made
//    if ( pSymbolFound )
//    {
//      break ; 
//    }
    
    // No point of continuing at all 
    if ( !m_pInsecureInstBugType )
    {
      MSEC_DEBUG( "redwud: ", "!m_pInsecureInstBugType" ) ;
      break ;
    }

    pSymbolFound = checkSQLStep( revCall, C, Ctx ) ;

    if ( !pSymbolFound )
    {
      break ; 
    }

    ProgramStateRef pProgState    = C.getState() ;

    if ( !pProgState )
    {
      MSEC_DEBUG( "redwud: ", "Unlikely but true, !pProgState" ) ; 
      break ;
    }

    //Report this instance
    CMSecCommon::reportInsecureInstance( pSymbolFound, C, C.addTransition( pProgState )
      , *m_pInsecureInstBugType, m_szReportDesc ) ;
  
  } while ( _PASSING_ ) ;

  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
}


bool iOSAppSecSQLInjectionChecker::isInsecureSymbol( const SymbolRef pSymbol, 
       const ProgramStateRef pProgState ) const
{
  //MSEC_DEBUG_FUNC("redwud: ","ENTER") ;
  bool bRet = false ;

  do
  {
    if ( !pSymbol || !pProgState )
    {
      //MSEC_DEBUG( "redwud: ", "Unlikely but true, !pProgState or !pSymbol" ) ; 
      break ;
    }
    
    const SQLInjectState *pSQLInjectState = pProgState ->get <StreamMap> ( pSymbol ) ; 
    
    // String or statement is not recorded
    if ( !pSQLInjectState )
    {
      //MSEC_DEBUG( "redwud: ", "!pSQLInjectState" ) ; 
      break ;
    }
      
    bRet = pSQLInjectState ->isNotSecure() ;

  } while( _PASSING_ ) ;

//  MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
  return bRet ;
} 

ProgramStateRef iOSAppSecSQLInjectionChecker::markSymbolInsecure( const SymbolRef pSymbol, ProgramStateRef pProgState, CheckerContext &C ) const
{
  ProgramStateRef pRet = NULL ;

  do 
  {
    if ( !pSymbol || !pProgState )
    {
      MSEC_DEBUG( "redwud: ", "!pSymbol" ) ; 
      break ; 
    }

    pProgState = pProgState ->set <StreamMap> ( pSymbol, SQLInjectState::getNotSecure() ) ;  

    if ( !pProgState )
    {
      MSEC_DEBUG( "redwud: ", "!pProgState" ) ; 
      break ; 
    }

    // Add transition of state
    C.addTransition( pProgState ) ;

    pRet = pProgState ; 
      
  } while ( _PASSING_ ) ;

  return pRet ;
}

// Use not for leaks but useful to remove our stored symbols 
void iOSAppSecSQLInjectionChecker::checkDeadSymbols(SymbolReaper &SymReaper,
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
void iOSAppSecSQLInjectionChecker::initIdentifierInfo(ASTContext &Ctx) const 
{
  do
  {
    //redwud: prevent the following to from gettting reinitialized
    if ( m_piiNSString )
    {
      break ;      
    }

    MSEC_DEBUG_FUNC("redwud: ","ENTER") ;

    m_piiNSString                  = &Ctx.Idents.get("NSString") ;
    m_piiNSMutableString           = &Ctx.Idents.get("NSMutableString") ;
    m_piiStringWithFormat          = &Ctx.Idents.get("stringWithFormat") ;
    m_piiLocalizedStringWithFormat = &Ctx.Idents.get("localizedStringWithFormat") ;     
    m_piiInitWithFormat            = &Ctx.Idents.get("initWithFormat") ;
    m_piiStringByAppendingFormat   = &Ctx.Idents.get("stringByAppendingFormat") ;
    m_piiAppendformat              = &Ctx.Idents.get("appendformat") ;
    m_piiSqlite3_prepare           = &Ctx.Idents.get("sqlite3_prepare") ;          
    m_piiSqlite3_prepare_v2        = &Ctx.Idents.get("sqlite3_prepare_v2") ;          
    m_piiSqlite3_prepare16         = &Ctx.Idents.get("sqlite3_prepare16") ;          
    m_piiSqlite3_prepare16_v2      = &Ctx.Idents.get("sqlite3_prepare16_v2") ;          
    m_piiSqlite3_bind_text         = &Ctx.Idents.get("sqlite3_bind_text") ;
    m_piiSqlite3_step              = &Ctx.Idents.get("sqlite3_step") ;

    MSEC_DEBUG_FUNC("redwud: ","EXIT") ;
  } while (_PASSING_) ;

}

// Through macro I guess this has to follow a certain naming convention
void ento::registeriOSAppSecSQLInjectionChecker(CheckerManager &mgr) 
{
  mgr.registerChecker<iOSAppSecSQLInjectionChecker>();
}

