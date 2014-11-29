//==- CheckSecuritySyntaxOnly.cpp - Basic security checks --------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines a set of flow-insensitive security checks.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/Analysis/AnalysisContext.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/Support/raw_ostream.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
//#define MSEC_DBG
#include "clang/StaticAnalyzer/Core/MSecCommon.h"
using namespace msec_cmn ;


using namespace clang ;
using namespace ento ;


namespace 
{
  struct ChecksFilter 
  {
    DefaultBool check_gets ;
    DefaultBool check_getpw ;
    DefaultBool check_strcpy ;
    DefaultBool check_sprintf ;
//     DefaultBool check_mktemp ;
//     DefaultBool check_mkstemp ;
//     DefaultBool check_rand ;
//     DefaultBool check_vfork ;
//     DefaultBool check_FloatLoopCounter ;
//     DefaultBool check_UncheckedReturn ;
  } ;
    
  class CWalkAST4BOF : public StmtVisitor< CWalkAST4BOF > 
  {
    enum { num_setids = 6 } ;

    BugReporter         &m_br ;
    AnalysisDeclContext *m_pADeclContext ;
    const ChecksFilter  &m_aggFilter ;
    const StringRef     m_szBugName ; //= ;
  
  public:
    CWalkAST4BOF(BugReporter &br, AnalysisDeclContext* ac, const ChecksFilter &f)
    : m_br           ( br )
    , m_pADeclContext( ac )
    , m_aggFilter    ( f )
    , m_szBugName    ( "Buffer Overflow" ) 
    { }
  
    // Statement visitor methods.
    void VisitCallExpr     (CallExpr *pCE) ;
    void VisitForStmt      (ForStmt *pStmt) ;
    void VisitCompoundStmt (CompoundStmt *pStmt) ;
    void VisitStmt         (Stmt *pStmt) 
    { VisitChildren(pStmt) ; }
  
    void VisitChildren(Stmt *pStmt) ;
  
    // Helpers.
    bool checkCall_strCommon(const CallExpr *pCE, const FunctionDecl *pFD, int iMaxArg = 3) ;
    bool checkCall_spriCommon(const CallExpr *pCE, const FunctionDecl *pFD, int iMaxArg = 3) ;
  
    typedef void (CWalkAST4BOF::*CHECK_FX)(const CallExpr *, const FunctionDecl *) ;
  
    // Checker-specific methods.
    void checkCall_gets   (const CallExpr *pCE, const FunctionDecl *pFD) ;
    void checkCall_getpw  (const CallExpr *pCE, const FunctionDecl *pFD) ;
    void checkCall_strcpy (const CallExpr *pCE, const FunctionDecl *pFD) ;
    void checkCall_strcat (const CallExpr *pCE, const FunctionDecl *pFD) ;
    void checkCall_sprintf(const CallExpr *pCE, const FunctionDecl *pFD) ; 
  } ;
} // end anonymous namespace

//===----------------------------------------------------------------------===//
// AST walking.
//===----------------------------------------------------------------------===//

void CWalkAST4BOF::VisitChildren(Stmt *pStmt) 
{
  for (Stmt::child_iterator I = pStmt ->child_begin(), E = pStmt ->child_end() ; I!=E ; ++I)
  {
    Stmt *pChild = *I ;

    if ( !pChild )
    {
      continue ;
    }

    Visit( pChild ) ;
  }
}

void CWalkAST4BOF::VisitCallExpr(CallExpr *pCE) 
{
  // Get the callee.  
  const FunctionDecl *pFD = pCE ->getDirectCallee() ;

  do
  {
    if ( !pFD )
    {
      break ;
    }

    // Get the name of the callee. If it's a builtin, strip off the prefix.
    IdentifierInfo *pII = pFD ->getIdentifier() ;

    if ( !pII )   // if no identifier, not a simple C function
    {
      break ;
    }

    StringRef Name = pII ->getName() ;

    if ( Name.startswith("__builtin_") )
    {
      Name = Name.substr(10) ;
    }

    // Set the evaluation function by switching on the callee name.
    CHECK_FX evalFunction = llvm::StringSwitch< CHECK_FX > ( Name )
      .Case   ("getpw",   &CWalkAST4BOF::checkCall_getpw)
      .Cases  ("gets",    "fgets", &CWalkAST4BOF::checkCall_gets)
      .Cases  ("strcpy",  "__strcpy_chk",  "strncpy",  &CWalkAST4BOF::checkCall_strcpy)
      .Cases  ("strcat",  "__strcat_chk",  "strncat",  &CWalkAST4BOF::checkCall_strcat)
    //  .Cases  ("sprintf", "vsprintf", &CWalkAST4BOF::checkCall_sprintf)
      .Cases  ("sprintf", "__sprintf_chk", "vsprintf", "__vsprintf_chk",  &CWalkAST4BOF::checkCall_sprintf)
      .Default(NULL) ;

    // If the callee isn't defined, it is not of security concern.
    // Check and evaluate the call.
    if ( evalFunction )
    {
      // redwud: Personally I interpret this as the following:
      // 1. Takes the offset of the corresponding method and place it to a function pointer: evalFunction
      // 2. Retrieve the offset via *evalFunction and make the this as the base and make it point to it
      // 3. The * actually makes the call, it seems this resembles Objective-C messaging
      // 4. Other impression is this notation/operator seems to be fixed/unary for object's function pointer
      //    and can't be broken down in simple pieces. e.g. -> first before *
      //    One more thing, because there is no basic type defined, it seems that the compiler makes an 
      //    intermediate type, before executing the call.
      (this ->*evalFunction)( pCE, pFD ) ;
    }

    // Recurse and check children.
    VisitChildren( pCE ) ;

  } while ( _PASSING_ ) ;
}

void CWalkAST4BOF::VisitCompoundStmt(CompoundStmt *pStmt) 
{
  for (Stmt::child_iterator I = pStmt->child_begin(), E = pStmt->child_end() ; I!=E ; ++I)
  {
    Stmt *pChild = *I ;

    if ( !pChild ) 
    {
      continue ;
    }

    //TODO: Confirm if this fx() is really necessary
    // if ( CallExpr *pCE = dyn_cast<CallExpr>( pChild ) )
    // {
    //   checkUncheckedReturnValue( pCE ) ;
    // }
    
    Visit( pChild ) ;
  }
}

void CWalkAST4BOF::VisitForStmt(ForStmt *pFStmt) 
{
//  checkLoopConditionForFloat( pFStmt ) ;

  // Recurse and check children.
  VisitChildren( pFStmt ) ;
}


//===----------------------------------------------------------------------===//
// Check: Any use of 'gets' is insecure.
// Originally: <rdar://problem/6335715>
// Implements (part of): 300-BSI (buildsecurityin.us-cert.gov)
// CWE-242: Use of Inherently Dangerous Function
//===----------------------------------------------------------------------===//

void CWalkAST4BOF::checkCall_gets(const CallExpr *pCE, const FunctionDecl *pFD) 
{
  do
  {
    if ( !m_aggFilter.check_gets )
    {
      break ;
    }

    const FunctionProtoType *pFPT = pFD ->getType() ->getAs< FunctionProtoType >() ;
    
    if ( !pFPT )
    {
      break ;
    }

    unsigned iParams = pFPT ->getNumParams() ; 
    
    // Verify that the function takes a appropriate number of argument (gets and fgets).
    // char *fgets(char * __restrict, int, FILE *); 
    // char* gets(char* str );
    if ( !((iParams == 1) || (iParams == 3)) ) // Should only be 1 or 3
    {
      break ;
    }

    // 
    // Is the first argument a 'char*'?
    // 
    const PointerType *pPT = pFPT ->getParamType(0) ->getAs< PointerType >() ;
    
    if ( !pPT )
    {
      break ;
    }
    
    if ( pPT ->getPointeeType().getUnqualifiedType() != m_br.getContext().CharTy )
    {
      break ;
    }
    
    //
    //  Add more checking for other parameters as for fgets()
    // 
    const IdentifierInfo *idFx = pFD ->getIdentifier() ;
 
    if ( idFx == &m_br.getContext().Idents.get( "fgets" ) )
    {
  
      // Is second paramter integral
      if ( !(pFPT ->getParamType(1) -> isIntegralOrUnscopedEnumerationType()) )
      {
        break ; 
      }

      // Is third parameter a pointer to FILE? 
      pPT = pFPT ->getParamType(2) ->getAs< PointerType >() ;

      if ( !pPT )
      {
        MSEC_DEBUG( "redwud: ", "######## this is fgets!!!!!!!" ) ;
        break ; 
      }

      // MSEC_DEBUG( "redwud: ", "######## this is fgets!!!!!!!" ) ;
      const IdentifierInfo *idFile = &m_br.getContext().Idents.get( "__sFILE" ) ;
      const IdentifierInfo *idBase = pPT ->getPointeeType().getBaseTypeIdentifier() ;
      
      if ( idFile != idBase )
      {
      
        MSEC_DEBUG("redwud: ","idFile != idBase " << idBase ->getName() ) ;
        MSEC_DEBUG( "redwud: ", "######## this is fgets!!!!!!!" ) ;
        break ;
      }

    }

    // Issue a warning.
    PathDiagnosticLocation CELoc =
      PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;

    m_br.EmitBasicReport( m_pADeclContext->getDecl(),
                          "Potential buffer overflow in calling gets() or fgets()",
                          m_szBugName ,
                          "Call to function gets() or fgets() is extremely insecure as it can "
                          "always result in a buffer overflow. Additionally, calling fgets() may result "
                          "to buffer overflow if not handled carefully. CWE-242",
                          CELoc, pCE->getCallee()->getSourceRange() ) ;
  
  } while ( _PASSING_ ) ;
}


   // do
   // {
   //   
   // } while ( _PASSING_ ) ;

//===----------------------------------------------------------------------===//
// Check: Any use of 'getpwd' is insecure.
// CWE-477: Use of Obsolete Functions
//===----------------------------------------------------------------------===//

void CWalkAST4BOF::checkCall_getpw(const CallExpr *pCE, const FunctionDecl *pFD) 
{
  do
  {
    if ( !m_aggFilter.check_getpw )
    {
      break ;
    }

    const FunctionProtoType *pFPT = pFD ->getType() ->getAs< FunctionProtoType >() ;
    
    if ( !pFPT )
    {
      break ;
    }

    // Verify that the function takes two arguments.
    if ( pFPT ->getNumParams() != 2 )
    {
      break ;
    }

    // Verify the first argument type is integer.
    if ( !pFPT ->getParamType(0) ->isIntegralOrUnscopedEnumerationType() )
    {
      break ;
    }

    // Verify the second argument type is char*.
    const PointerType *pPT = pFPT ->getParamType(1) ->getAs< PointerType >() ;
    
    if ( !pPT )
    {
      break ;
    }

    if (pPT->getPointeeType().getUnqualifiedType() != m_br.getContext().CharTy)
    {
      break ;
    }

    // Issue a warning.
    PathDiagnosticLocation CELoc =
      PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;

    m_br.EmitBasicReport(m_pADeclContext->getDecl(),
                       "Potential buffer overflow in call to getpw()",
                       m_szBugName,
                       "The getpw() function is dangerous as it may overflow the "
                       "provided buffer. It is obsoleted by getpwuid().",
                       CELoc, pCE->getCallee()->getSourceRange()) ;
  } while ( _PASSING_ ) ;
}


//===----------------------------------------------------------------------===//
// Check: Any use of 'strcpy' is insecure.
//
// CWE-119: Improper Restriction of Operations within 
// the Bounds of a Memory Buffer 
//===----------------------------------------------------------------------===//

void CWalkAST4BOF::checkCall_strcpy(const CallExpr *pCE, const FunctionDecl *pFD) 
{
  do                      
  {
    if ( !m_aggFilter.check_strcpy )
    {          
      break ;
    }

    if ( !checkCall_strCommon(pCE, pFD) )
    {
      break ;
    }
    
    // Issue a warning.
    PathDiagnosticLocation CELoc =
      PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;
    
    m_br.EmitBasicReport(m_pADeclContext->getDecl(),
                       "Potential insecure memory buffer bounds restriction in "
                       "a call to strcpy() or strncpy() ",
                       m_szBugName,
                       "Call to functions: strcpy() and strncpy() are insecure "
                       "as it does not provide bounding of the memory buffer. Replace "
                       "unbounded copy functions with analogous functions that "
                       "support length arguments such as strlcpy(). strncpy() does "
                       "guarantee a null-terminator thus will still lead to BOF. CWE-119. ",
                       CELoc, pCE->getCallee()->getSourceRange()) ;

  } while ( _PASSING_ ) ;
}

//===----------------------------------------------------------------------===//
// Check: Any use of strcat() is insecure.
//
// CWE-119: Improper Restriction of Operations within 
// the Bounds of a Memory Buffer 
//===----------------------------------------------------------------------===//

void CWalkAST4BOF::checkCall_strcat(const CallExpr *pCE, const FunctionDecl *pFD) 
{
  do
  {
    if ( !m_aggFilter.check_strcpy )
    {
      break ;
    }

    if ( !checkCall_strCommon(pCE, pFD) )
    {
      break ;
    }

    // Issue a warning.
    PathDiagnosticLocation CELoc =
      PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;

    m_br.EmitBasicReport(m_pADeclContext->getDecl(),
                       "Potential insecure memory buffer bounds restriction in "
                       "call strcat() or strncat()",
                       m_szBugName,
                       "Call to function strcat() or strncat() is insecure as it does not "
                       "provide bounding of the memory buffer. Replace "
                       "unbounded copy functions with analogous functions that "
                       "support length arguments such as strlcat(). CWE-119.",
                       CELoc, pCE->getCallee()->getSourceRange()) ;
  
  } while ( _PASSING_ ) ;
}

//===----------------------------------------------------------------------===//
// Check: Any use of 'sprintf' is insecure.
//
// CWE-193: Off-by-one Error 
// CWE-676: Use of Potentially Dangerous Function
//===----------------------------------------------------------------------===//

void CWalkAST4BOF::checkCall_sprintf(const CallExpr *pCE, const FunctionDecl *pFD) 
{

  MSEC_DEBUG_FUNC( "redwud: ", "ENTER" ) ;

  do
  {
    if ( !m_aggFilter.check_sprintf )
    {
      MSEC_DEBUG( "redwud: ", "!m_aggFilter.check_sprintf" ) ;
      break ;
    }

    // This is common with sprintf and strcpy to both have 2 string
    // in the beginning, but 4 parameters for the check version and 5 for vsprintf
    if ( !checkCall_spriCommon(pCE, pFD, 5) )
    {
      MSEC_DEBUG( "redwud: ", "!checkCall_strCommon(pCE, pFD)" ) ;
      break ;
    }

    // Issue a warning.
    PathDiagnosticLocation CELoc =
      PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;

    m_br.EmitBasicReport( m_pADeclContext->getDecl(),
                          "sprintf() and vsprintf() does not check for buffer boundaries "
                          "therefore it is also vulnerable to buffer overflow.",
                          m_szBugName,
                          "Call to function sprintf() or vsprintf() is insecure as it "
                          "does not provide bounding of the memory buffer. Replace "
                          "unbounded copy functions with analogous functions that "
                          "support length arguments such as snprintf(). CWE-676 and 193.",
                          CELoc, pCE ->getCallee() ->getSourceRange()) ;
  
  } while ( _PASSING_ ) ;
  
  MSEC_DEBUG_FUNC( "redwud: ", "EXIT" ) ;
}

//===----------------------------------------------------------------------===//
// Common check for str* functions with no bounds parameters.
//===----------------------------------------------------------------------===//

// Returns true if it belongs to target function else false
bool CWalkAST4BOF::checkCall_strCommon( const CallExpr *pCE, const FunctionDecl *pFD, int iMaxArg ) 
{
  const FunctionProtoType *pFPT = pFD->getType()->getAs<FunctionProtoType>() ;
  bool bRet = false ;

  do
  {
    if ( !pFPT )
    {
      break ;
    }

    // Verify the function takes two arguments, three in the _chk version.
    int iArgs = pFPT ->getNumParams() ;

    if ( (iArgs != 2) && (iArgs != iMaxArg) )
    {
      MSEC_DEBUG( "redwud: ", "(iArgs != 2) && (iArgs != 3): " << iArgs ) ;
      break ;
    }

    // Assume from here there should be no more 
    bRet = true ;

    // Verify the type for both arguments.
    for (int i = 0 ; i < 2 ; i++) 
    {
      // MSEC_DEBUG( "redwud: ", "dumping param type: " << i << " " ) ;
      // pFPT ->getParamType(i) ->dump() ;

      // Verify that the arguments are pointers.
      const PointerType *pPT = pFPT ->getParamType(i) ->getAs< PointerType >() ;
      
      if ( !pPT )
      {
        MSEC_DEBUG( "redwud: ", "!pPT" ) ;
        bRet = false ;
        break ;
      }

      // Verify that the argument is a 'char*'.
      if ( pPT ->getPointeeType().getUnqualifiedType() != m_br.getContext().CharTy )
      {
        MSEC_DEBUG( "redwud: ", "pPT ->getPointeeType().getUnqualifiedType() != m_br.getContext().CharTy" ) ;
        bRet = false ;
        break ;
      }
    }
  } while ( _PASSING_ ) ;

  return bRet ;
}


// QualType CWalkAST4BOF::getCoreType(QualType Ty)
// {
//   do 
//   {
//     if (Ty ->isPointerType() || Ty->isReferenceType())
//         Ty = Ty->getPointeeType();
//     else if (Ty->isArrayType())
//         Ty = Ty->castAsArrayTypeUnsafe()->getElementType();
//     else
//         return Ty.withoutLocalFastQualifiers();
//   } while (true);
// }

//===----------------------------------------------------------------------===//
// Common check for sprintf* functions with no bounds parameters.
//===----------------------------------------------------------------------===//

// Returns true if it belongs to target function else false
// Temporarily marked as common
// TODO: Rename to appropriate name or merge to caller
bool CWalkAST4BOF::checkCall_spriCommon( const CallExpr *pCE, const FunctionDecl *pFD, int iMaxArg ) 
{
  const FunctionProtoType *pFPT = pFD->getType()->getAs<FunctionProtoType>() ;
  bool bRet = false ;

  do
  {
    if ( !pFPT )
    {
      break ;
    }

    // Verify the function takes two arguments, three in the _chk version.
    int iArgs = pFPT ->getNumParams() ;

    if ( (iArgs < 2) || (iArgs > iMaxArg) )
    {
      MSEC_DEBUG( "redwud: ", "(iArgs != 2) && (iArgs != ): " << iArgs << " " << iMaxArg) ;
      break ;
    }

    // Assume from here there should be no more 
    bRet = true ;

    // Verify the type for both arguments.
    for (int i = 0 ; i < iArgs ; i++) 
    {
      // MSEC_DEBUG( "redwud: ", "dumping param type(spri): " << i << " " ) ;
      // pFPT ->getParamType(i) ->dump() ;
      
      QualType qtParam = pFPT ->getParamType( i ) ;

      //
      // If the parameter is a pointer then it should be a pointer to char (char *)
      //
      const PointerType *pPT = qtParam ->getAs< PointerType >() ;
      
      if ( pPT )
      {
        ASTContext &ctxtAST    = m_br.getContext() ;
        QualType qtUnqualified = pPT ->getPointeeType().getUnqualifiedType() ; 
        const TagType *pTT     = qtUnqualified ->getAs< TagType >() ;

        // Verify that the argument is a 'char *' or '__va_list_tag *'
        // NOTE: Only way to to know va_list for now is it is a tag
        //       and it is unique enough for now
        // FIXME: Determine real va_list ctxtAST.VaListTagTy has struct in when dumped,
        //       
        // if ( (qtUnqualified != ctxtAST.CharTy) && (qtUnqualified != ctxtAST.VaListTagTy.withoutLocalFastQualifiers() ) )
        
        if ( (qtUnqualified != ctxtAST.CharTy) && (!pTT) )
        {
          MSEC_DEBUG( "redwud: ", "(qtUnqualified != ctxtAST.CharTy)..." ) ;
          qtUnqualified ->dump() ;

          bRet = false ;
          break ;
        }
      }
      else
      {
        if ( !(qtParam -> isIntegralOrUnscopedEnumerationType()) )
        {
          MSEC_DEBUG( "redwud: ", "!(qtParam -> isIntegralOrUnscopedEnumerationType())" ) ;
          bRet = false ;
          break ;
        }
      }
    }
  } while ( _PASSING_ ) ;

  return bRet ;
}



//===----------------------------------------------------------------------===//
// iOSAppSecBufferOverflowChecker
//===----------------------------------------------------------------------===//

namespace 
{
  class iOSAppSecBufferOverflowChecker : public Checker<check::ASTCodeBody> 
  {
  public:
    ChecksFilter m_aggFilter ;
    
    void checkASTCodeBody(const Decl *pDecl, AnalysisManager& mgr, BugReporter &br) const 
    {
      CWalkAST4BOF walker( br, mgr.getAnalysisDeclContext( pDecl ), m_aggFilter ) ;

      walker.Visit( pDecl ->getBody() ) ;
    }
  } ;
} // end of anonymous namespace


#define REGISTER_CHECKER(name) \
  rMgr.registerChecker<iOSAppSecBufferOverflowChecker>() ->m_aggFilter.check_##name = true ;

// Through macro I guess this has to follow a certain naming convention
// This comment does not make sense
void ento::registeriOSAppSecBufferOverflowChecker(CheckerManager &rMgr) 
{
   REGISTER_CHECKER( gets    )
   REGISTER_CHECKER( strcpy  )
   REGISTER_CHECKER( getpw   )
   REGISTER_CHECKER( sprintf )
//   REGISTER_CHECKER(mkstemp)
}


// #define REGISTER_CHECKER(name) \
// void ento::register##name(CheckerManager &mgr) {\
//   mgr.registerChecker<iOSAppSecBufferOverflowChecker>()->m_aggFilter.check_##name = true ;\
// }
// REGISTER_CHECKER(gets)
// REGISTER_CHECKER(getpw)
// REGISTER_CHECKER(mkstemp)
// REGISTER_CHECKER(mktemp)
// REGISTER_CHECKER(strcpy)
// REGISTER_CHECKER(rand)
// REGISTER_CHECKER(vfork)
// REGISTER_CHECKER(FloatLoopCounter)
// REGISTER_CHECKER(UncheckedReturn)



///////////// Discarded Codes ///////////// 


// do
// {
//
//   {
//     break ;
//   }
// } while ( _PASSING_ ) ;
//

// static bool isArc4RandomAvailable(const ASTContext &Ctx) 
// {
//   const llvm::Triple &T = Ctx.getTargetInfo().getTriple() ;
// 
//   return T.getVendor() == llvm::Triple::Apple ||
//          T.getOS() == llvm::Triple::FreeBSD ||
//          T.getOS() == llvm::Triple::NetBSD ||
//          T.getOS() == llvm::Triple::OpenBSD ||
//          T.getOS() == llvm::Triple::Bitrig ||
//          T.getOS() == llvm::Triple::DragonFly ;
// }



//===----------------------------------------------------------------------===//
// Check: floating poing variable used as loop counter.
// Originally: <rdar://problem/6336718>
// Implements: CERT security coding advisory FLP-30.
//===----------------------------------------------------------------------===//

//TODO: Fix with _PASSING_
// static const DeclRefExpr* getIncrementedVar(const Expr *expr, const VarDecl *x, const VarDecl *y) 
// {
//   expr = expr->IgnoreParenCasts() ;
// 
//   if (const BinaryOperator *B = dyn_cast<BinaryOperator>(expr)) 
//   {
//     if (!(B->isAssignmentOp() || B->isCompoundAssignmentOp() ||
//           B->getOpcode() == BO_Comma))
//       return NULL ;
// 
//     if (const DeclRefExpr *lhs = getIncrementedVar(B->getLHS(), x, y))
//       return lhs ;
// 
//     if (const DeclRefExpr *rhs = getIncrementedVar(B->getRHS(), x, y))
//       return rhs ;
// 
//     return NULL ;
//   }
// 
//   if (const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(expr)) {
//     const NamedDecl *ND = DR->getDecl() ;
//     return ND == x || ND == y ? DR : NULL ;
//   }
// 
//   if (const UnaryOperator *U = dyn_cast<UnaryOperator>(expr))
//     return U->isIncrementDecrementOp()
//       ? getIncrementedVar(U->getSubExpr(), x, y) : NULL ;
// 
//   return NULL ;
// }

/// CheckLoopConditionForFloat - This check looks for 'for' statements that
///  use a floating point variable as a loop counter.
///  CERT: FLP30-C, FLP30-CPP.
///

//TODO: Fix with _PASSING_
// void CWalkAST4BOF::checkLoopConditionForFloat(const ForStmt *pFStmt) 
// {
//   if (!m_aggFilter.check_FloatLoopCounter)
//     return ;
// 
//   // Does the loop have a condition?
//   const Expr *condition = pFStmt->getCond() ;
// 
//   if (!condition)
//     return ;
// 
//   // Does the loop have an increment?
//   const Expr *increment = pFStmt->getInc() ;
// 
//   if (!increment)
//     return ;
// 
//   // Strip away '()' and casts.
//   condition = condition->IgnoreParenCasts() ;
//   increment = increment->IgnoreParenCasts() ;
// 
//   // Is the loop condition a comparison?
//   const BinaryOperator *B = dyn_cast<BinaryOperator>(condition) ;
// 
//   if (!B)
//     return ;
// 
//   // Is this a comparison?
//   if (!(B->isRelationalOp() || B->isEqualityOp()))
//     return ;
// 
//   // Are we comparing variables?
//   const DeclRefExpr *drLHS =
//     dyn_cast<DeclRefExpr>(B->getLHS()->IgnoreParenLValueCasts()) ;
//   const DeclRefExpr *drRHS =
//     dyn_cast<DeclRefExpr>(B->getRHS()->IgnoreParenLValueCasts()) ;
// 
//   // Does at least one of the variables have a floating point type?
//   drLHS = drLHS && drLHS->getType()->isRealFloatingType() ? drLHS : NULL ;
//   drRHS = drRHS && drRHS->getType()->isRealFloatingType() ? drRHS : NULL ;
// 
//   if (!drLHS && !drRHS)
//     return ;
// 
//   const VarDecl *vdLHS = drLHS ? dyn_cast<VarDecl>(drLHS->getDecl()) : NULL ;
//   const VarDecl *vdRHS = drRHS ? dyn_cast<VarDecl>(drRHS->getDecl()) : NULL ;
// 
//   if (!vdLHS && !vdRHS)
//     return ;
// 
//   // Does either variable appear in increment?
//   const DeclRefExpr *drInc = getIncrementedVar(increment, vdLHS, vdRHS) ;
// 
//   if (!drInc)
//     return ;
// 
//   // Emit the error.  First figure out which DeclRefExpr in the condition
//   // referenced the compared variable.
//   assert(drInc->getDecl()) ;
//   const DeclRefExpr *drCond = vdLHS == drInc->getDecl() ? drLHS : drRHS ;
// 
//   SmallVector<SourceRange, 2> ranges ;
//   SmallString<256> sbuf ;
//   llvm::raw_svector_ostream os(sbuf) ;
// 
//   os << "Variable '" << drCond->getDecl()->getName()
//      << "' with floating point type '" << drCond->getType().getAsString()
//      << "' should not be used as a loop counter" ;
// 
//   ranges.push_back(drCond->getSourceRange()) ;
//   ranges.push_back(drInc->getSourceRange()) ;
// 
//   const char *bugType = "Floating point variable used as loop counter" ;
// 
//   PathDiagnosticLocation FSLoc =
//     PathDiagnosticLocation::createBegin(pFStmt, m_br.getSourceManager(), m_pADeclContext) ;
//   m_br.EmitBasicReport(m_pADeclContext->getDecl(),
//                      bugType, "Buffer Overflow", os.str(),
//                      FSLoc, ranges) ;
// }



//===----------------------------------------------------------------------===//
// Check: Any use of 'mktemp' is insecure.  It is obsoleted by mkstemp().
// CWE-377: Insecure Temporary File
//===----------------------------------------------------------------------===//

//TODO: Fix with _PASSING_
// void CWalkAST4BOF::checkCall_mktemp(const CallExpr *pCE, const FunctionDecl *pFD) 
// {
//   if (!m_aggFilter.check_mktemp) {
//     // Fall back to the security check of looking for enough 'X's in the
//     // format string, since that is a less severe warning.
//     checkCall_mkstemp(pCE, pFD) ;
//     return ;
//   }
// 
//   const FunctionProtoType *pFPT = pFD->getType()->getAs<FunctionProtoType>() ;
//   if(!pFPT)
//     return ;
// 
//   // Verify that the function takes a single argument.
//   if (pFPT->getNumParams() != 1)
//     return ;
// 
//   // Verify that the argument is Pointer Type.
//   const PointerType *pPT = pFPT->getParamType(0)->getAs<PointerType>() ;
//   if (!pPT)
//     return ;
// 
//   // Verify that the argument is a 'char*'.
//   if (pPT->getPointeeType().getUnqualifiedType() != m_br.getContext().CharTy)
//     return ;
// 
//   // Issue a waring.
//   PathDiagnosticLocation CELoc =
//     PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;
//   m_br.EmitBasicReport(m_pADeclContext->getDecl(),
//                      "Potential insecure temporary file in call 'mktemp'",
//                      "Buffer Overflow",
//                      "Call to function 'mktemp' is insecure as it always "
//                      "creates or uses insecure temporary file.  Use 'mkstemp' "
//                      "instead",
//                      CELoc, pCE->getCallee()->getSourceRange()) ;
// }


//===----------------------------------------------------------------------===//
// Check: Use of 'mkstemp', 'mktemp', 'mkdtemp' should contain at least 6 X's.
//===----------------------------------------------------------------------===//

//TODO: Fix with _PASSING_
// void CWalkAST4BOF::checkCall_mkstemp(const CallExpr *pCE, const FunctionDecl *pFD) 
// {
//   if (!m_aggFilter.check_mkstemp)
//     return ;
// 
//   StringRef Name = pFD->getIdentifier()->getName() ;
//   std::pair<signed, signed> ArgSuffix =
//     llvm::StringSwitch<std::pair<signed, signed> >(Name)
//       .Case("mktemp", std::make_pair(0,-1))
//       .Case("mkstemp", std::make_pair(0,-1))
//       .Case("mkdtemp", std::make_pair(0,-1))
//       .Case("mkstemps", std::make_pair(0,1))
//       .Default(std::make_pair(-1, -1)) ;
//   
//   assert(ArgSuffix.first >= 0 && "Unsupported function") ;
// 
//   // Check if the number of arguments is consistent with out expectations.
//   unsigned numArgs = pCE->getNumArgs() ;
//   if ((signed) numArgs <= ArgSuffix.first)
//     return ;
//   
//   const StringLiteral *strArg =
//     dyn_cast<StringLiteral>(pCE->getArg((unsigned)ArgSuffix.first)
//                               ->IgnoreParenImpCasts()) ;
//   
//   // Currently we only handle string literals.  It is possible to do better,
//   // either by looking at references to const variables, or by doing real
//   // flow analysis.
//   if (!strArg || strArg->getCharByteWidth() != 1)
//     return ;
// 
//   // Count the number of X's, taking into account a possible cutoff suffix.
//   StringRef str = strArg->getString() ;
//   unsigned numX = 0 ;
//   unsigned n = str.size() ;
// 
//   // Take into account the suffix.
//   unsigned suffix = 0 ;
//   if (ArgSuffix.second >= 0) {
//     const Expr *suffixEx = pCE->getArg((unsigned)ArgSuffix.second) ;
//     llvm::APSInt Result ;
//     if (!suffixEx->EvaluateAsInt(Result, m_br.getContext()))
//       return ;
//     // FIXME: Issue a warning.
//     if (Result.isNegative())
//       return ;
//     suffix = (unsigned) Result.getZExtValue() ;
//     n = (n > suffix) ? n - suffix : 0 ;
//   }
//   
//   for (unsigned i = 0 ; i < n ; ++i)
//     if (str[i] == 'X') ++numX ;
//   
//   if (numX >= 6)
//     return ;
//   
//   // Issue a warning.
//   PathDiagnosticLocation CELoc =
//     PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;
//   SmallString<512> buf ;
//   llvm::raw_svector_ostream out(buf) ;
//   out << "Call to '" << Name << "' should have at least 6 'X's in the"
//     " format string to be secure (" << numX << " 'X'" ;
//   if (numX != 1)
//     out << 's' ;
//   out << " seen" ;
//   if (suffix) {
//     out << ", " << suffix << " character" ;
//     if (suffix > 1)
//       out << 's' ;
//     out << " used as a suffix" ;
//   }
//   out << ')' ;
//   m_br.EmitBasicReport(m_pADeclContext->getDecl(),
//                      "Insecure temporary file creation", "Buffer Overflow",
//                      out.str(), CELoc, strArg->getSourceRange()) ;
// }


//===----------------------------------------------------------------------===//
// Check: Linear congruent random number generators should not be used
// Originally: <rdar://problem/63371000>
// CWE-338: Use of cryptographically weak prng
//===----------------------------------------------------------------------===//

//TODO: Fix with _PASSING_
// void CWalkAST4BOF::checkCall_rand(const CallExpr *pCE, const FunctionDecl *pFD) 
// {
//   if (!m_aggFilter.check_rand || !CheckRand)
//     return ;
// 
//   const FunctionProtoType *FTP = pFD->getType()->getAs<FunctionProtoType>() ;
//   if (!FTP)
//     return ;
// 
//   if (FTP->getNumParams() == 1) {
//     // Is the argument an 'unsigned short *'?
//     // (Actually any integer type is allowed.)
//     const PointerType *pPT = FTP->getParamType(0)->getAs<PointerType>() ;
//     if (!pPT)
//       return ;
// 
//     if (! pPT->getPointeeType()->isIntegralOrUnscopedEnumerationType())
//       return ;
//   } else if (FTP->getNumParams() != 0)
//     return ;
// 
//   // Issue a warning.
//   SmallString<256> buf1 ;
//   llvm::raw_svector_ostream os1(buf1) ;
//   os1 << '\'' << *pFD << "' is a poor random number generator" ;
// 
//   SmallString<256> buf2 ;
//   llvm::raw_svector_ostream os2(buf2) ;
//   os2 << "Function '" << *pFD
//       << "' is obsolete because it implements a poor random number generator."
//       << "  Use 'arc4random' instead" ;
// 
//   PathDiagnosticLocation CELoc =
//     PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;
//   m_br.EmitBasicReport(m_pADeclContext->getDecl(), os1.str(), "Buffer Overflow", os2.str(),
//                      CELoc, pCE->getCallee()->getSourceRange()) ;
// }



//===----------------------------------------------------------------------===//
// Check: 'random' should not be used
// Originally: <rdar://problem/63371000>
//===----------------------------------------------------------------------===//

//TODO: Fix with _PASSING_
// void CWalkAST4BOF::checkCall_random(const CallExpr *pCE, const FunctionDecl *pFD) 
// {
//   if (!CheckRand || !m_aggFilter.check_rand)
//     return ;
// 
//   const FunctionProtoType *FTP = pFD->getType()->getAs<FunctionProtoType>() ;
//   if (!FTP)
//     return ;
// 
//   // Verify that the function takes no argument.
//   if (FTP->getNumParams() != 0)
//     return ;
// 
//   // Issue a warning.
//   PathDiagnosticLocation CELoc =
//     PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;
//   m_br.EmitBasicReport(m_pADeclContext->getDecl(),
//                      "'random' is not a secure random number generator",
//                      "Buffer Overflow",
//                      "The 'random' function produces a sequence of values that "
//                      "an adversary may be able to predict.  Use 'arc4random' "
//                      "instead", CELoc, pCE->getCallee()->getSourceRange()) ;
// }


//===----------------------------------------------------------------------===//
// Check: 'vfork' should not be used.
// POS33-C: Do not use vfork().
//===----------------------------------------------------------------------===//

//TODO: Fix with _PASSING_
// void CWalkAST4BOF::checkCall_vfork(const CallExpr *pCE, const FunctionDecl *pFD) 
// {
//   if (!m_aggFilter.check_vfork)
//     return ;
// 
//   // All calls to vfork() are insecure, issue a warning.
//   PathDiagnosticLocation CELoc =
//     PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;
//   m_br.EmitBasicReport(m_pADeclContext->getDecl(),
//                      "Potential insecure implementation-specific behavior in "
//                      "call 'vfork'",
//                      "Buffer Overflow",
//                      "Call to function 'vfork' is insecure as it can lead to "
//                      "denial of service situations in the parent process. "
//                      "Replace calls to vfork with calls to the safer "
//                      "'posix_spawn' function",
//                      CELoc, pCE->getCallee()->getSourceRange()) ;
// }

//===----------------------------------------------------------------------===//
// Check: Should check whether privileges are dropped successfully.
// Originally: <rdar://problem/6337132>
//===----------------------------------------------------------------------===//

//TODO: Fix with _PASSING_
// void CWalkAST4BOF::checkUncheckedReturnValue(CallExpr *pCE) 
// {
//   if (!m_aggFilter.check_UncheckedReturn)
//     return ;
//   
//   const FunctionDecl *pFD = pCE->getDirectCallee() ;
//   if (!pFD)
//     return ;
// 
//   if (II_setid[0] == NULL) {
//     static const char * const identifiers[num_setids] = {
//       "setuid", "setgid", "seteuid", "setegid",
//       "setreuid", "setregid"
//     } ;
// 
//     for (size_t i = 0 ; i < num_setids ; i++)
//       II_setid[i] = &m_br.getContext().Idents.get(identifiers[i]) ;
//   }
// 
//   const IdentifierInfo *id = pFD->getIdentifier() ;
//   size_t identifierid ;
// 
//   for (identifierid = 0 ; identifierid < num_setids ; identifierid++)
//     if (id == II_setid[identifierid])
//       break ;
// 
//   if (identifierid >= num_setids)
//     return ;
// 
//   const FunctionProtoType *FTP = pFD->getType()->getAs<FunctionProtoType>() ;
//   if (!FTP)
//     return ;
// 
//   // Verify that the function takes one or two arguments (depending on
//   //   the function).
//   if (FTP->getNumParams() != (identifierid < 4 ? 1 : 2))
//     return ;
// 
//   // The arguments must be integers.
//   for (unsigned i = 0 ; i < FTP->getNumParams() ; i++)
//     if (!FTP->getParamType(i)->isIntegralOrUnscopedEnumerationType())
//       return ;
// 
//   // Issue a warning.
//   SmallString<256> buf1 ;
//   llvm::raw_svector_ostream os1(buf1) ;
//   os1 << "Return value is not checked in call to '" << *pFD << '\'' ;
// 
//   SmallString<256> buf2 ;
//   llvm::raw_svector_ostream os2(buf2) ;
//   os2 << "The return value from the call to '" << *pFD
//       << "' is not checked.  If an error occurs in '" << *pFD
//       << "', the following code may execute with unexpected privileges" ;
// 
//   PathDiagnosticLocation CELoc =
//     PathDiagnosticLocation::createBegin(pCE, m_br.getSourceManager(), m_pADeclContext) ;
//   m_br.EmitBasicReport(m_pADeclContext->getDecl(), os1.str(), "Buffer Overflow", os2.str(),
//                      CELoc, pCE->getCallee()->getSourceRange()) ;
// }


