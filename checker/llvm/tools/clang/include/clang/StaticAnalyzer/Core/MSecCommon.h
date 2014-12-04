//==--- InterCheckerAPI.h ---------------------------------------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// This file allows introduction of checker dependencies. It contains APIs for
// inter-checker communications.
//===----------------------------------------------------------------------===//

#ifndef MSEC_COMMON_H
#define MSEC_COMMON_H

//Turn off warning using typeof as extension 
#pragma clang diagnostic ignored "-Wlanguage-extension-token"


#include <string.h>
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"


#define _PASSING_ (0)
#define _INFINITY_ ;;
#define _countof( _obj_ ) (int)( sizeof(_obj_) / (sizeof( typeof( _obj_[0] ))) )
#define _countof_strict( _obj_, _typecast_ ) (_typecast_)( sizeof(_obj_) / (sizeof( typeof( _obj_[0] ))) )

#ifdef MSEC_DBG
  #define MSEC_DEBUG(_prefix_,_str_)      llvm::errs() <<"\n" << _prefix_ << strrchr(__FILE__,'/') << " \t" << __LINE__ << " " << _str_ ;
  #define MSEC_DEBUG_FUNC(_prefix_,_str_) llvm::errs() <<"\n" << _prefix_ << strrchr(__FILE__,'/') << " \t" << __LINE__ << " " << __FUNCTION__ << " " << _str_ ;
#else
  #define MSEC_DEBUG(_prefix_,_str_) 
  #define MSEC_DEBUG_FUNC(_prefix_,_str_)
#endif

#ifdef MSEC_INN_DBG
  #define MSEC_INN_DEBUG(_prefix_,_str_)      MSEC_DEBUG(_prefix_,_str_)      
  #define MSEC_INN_DEBUG_FUNC(_prefix_,_str_) MSEC_DEBUG_FUNC(_prefix_,_str_) 
#else
  #define MSEC_INN_DEBUG(_prefix_,_str_) 
  #define MSEC_INN_DEBUG_FUNC(_prefix_,_str_)
#endif

#define MAGICK_SYMBOL_REF (0xBEEF)


using namespace clang ;
using namespace ento ;


namespace msec_cmn 
{
  // 2 here is a special value that to my understanding denotes common type. 
  typedef SmallVector< IdentifierInfo *, 2> IdPtrVectorType ;
  typedef SmallVector< SymbolRef, 2>        SymbolRefVectorType ;

  /////////////////////////////////////////////////////
  class CMSecCommon
  {
  public:
  
    static std::string getStringFromSVal( const SVal &svalObject )
    {
      std::string szTemp ;
    
      llvm::raw_string_ostream osStr( szTemp ) ;
      
      svalObject.dumpToStream( osStr ) ;

      return osStr.str() ;
    }
    
    static bool isSValContains( const SVal &svalObject, const std::string &szString )
    {   
      bool bRet = false ;
     
      do
      { 
        if ( szString.empty() )
        {
          break ;
        }

        std::string szID = CMSecCommon::getStringFromSVal( svalObject ) ;
       
        if ( szID.empty() )
        {
          break ;
        }
    
        if ( szID.find( szString ) == std::string::npos )
        {
          break ;
        }  
        
        //Contains 
        bRet = true ;
         
      } while( _PASSING_ ) ;
    
      return bRet ;
    } //isValContains

    static SymbolRef conjureSymbolRef()
    {
      return ( (SymbolRef) MAGICK_SYMBOL_REF ) ;
    }

    static bool isConjuredSymbolRef( SymbolRef pSymbol )
    {
      return ( conjureSymbolRef() == pSymbol ) ; 
    }


    template <typename _base_type_>
    static  _base_type_ *conjurePtr()
    {
      return ( (_base_type_ *) MAGICK_SYMBOL_REF ) ;
    }

    template <typename _base_type_>
    static bool isConjuredPtr( const _base_type_ *pPtr )
    {
      return ( conjurePtr <_base_type_>() == pPtr ) ; 
    }

    static void reportInsecureInstance( SymbolRef pSymQuery, CheckerContext &C, ExplodedNode *pErrNode, BugType &rTheBug, StringRef szDesc )
    {
      do
      {
      
        if ( !pSymQuery || !pErrNode )
        {
          MSEC_INN_DEBUG("redwud: ", "Missed bug report!" ) ;
          break ;
        }
        
        BugReport *pReport = new BugReport( rTheBug, szDesc, pErrNode ) ;
        
        if ( !pReport )
        {
          MSEC_INN_DEBUG("redwud: ", "missed bug report!" ) ;
          break ;
        }
       
        if ( !isConjuredSymbolRef( pSymQuery ) )
        { 
          pReport ->markInteresting( pSymQuery ) ;  
        }
    
        C.emitReport( pReport ) ;
      
      } while ( _PASSING_ ) ;
    } //reportInsecureInstance


    static void reportInsecureInstance( BugType &rTheBug, StringRef szDesc, BugReporter &rBR, const Decl *pDecl )
    {
      MSEC_INN_DEBUG_FUNC("redwud: ","ENTER") ;

      do
      {
        PathDiagnosticLocation rPDL = PathDiagnosticLocation::createBegin( pDecl, rBR.getSourceManager());

        //FIXME: try to figure out what is wrong with the commented out code!
        //BugReport *pReport = new BugReport( rTheBug, szDesc, rPDL ) ;
        //
        //if ( !pReport )
        //{
        //  MSEC_INN_DEBUG("redwud: ", "missed bug report!" ) ;
        //  break ;
        //}
       
        //rBR.emitReport( pReport ) ;
        //rBR.FlushReports() ;

         rBR.EmitBasicReport( pDecl, rTheBug.getName(), rTheBug.getCategory(), 
             szDesc, rPDL ) ;

      } while ( _PASSING_ ) ;
      
      MSEC_INN_DEBUG_FUNC("redwud: ","EXIT") ;
    } //reportInsecureInstance

    static bool findIdentifierInDeclStmt(const DeclStmt *pDeclStmt, const IdentifierInfo *pInfo)
    {
      MSEC_INN_DEBUG_FUNC("redwud: ","ENTER") ;
      
      bool bRet = false ;
    
      for ( DeclStmt::const_decl_iterator pItem = pDeclStmt ->decl_begin(),
                                         pEndItem = pDeclStmt ->decl_end();
                                         pItem != pEndItem; ++pItem )
      {
        const NamedDecl *pNamedDecl = dyn_cast_or_null< NamedDecl >( *pItem ) ;
       
        if ( !pNamedDecl )
        {
          continue ;
        }
    
        if ( pNamedDecl ->getIdentifier() == pInfo )
        {
          bRet = true ;
          break ;
        }
      }
    
      MSEC_INN_DEBUG_FUNC("redwud: ","EXIT") ;
      return bRet ;
    }
    
    
    static bool findIdentifierInDeclRef(const DeclRefExpr *pDeclRef, const IdentifierInfo *pInfo)
    {
      bool bRet = false ;
     
      do
      {
        if ( !pDeclRef || !pInfo )
        {
          break ;
        }
       
        const NamedDecl *pFound = pDeclRef ->getFoundDecl() ;
       
        if ( !pFound )
        {
          break ;
        }
    
        if ( pFound ->getIdentifier() == pInfo )
        {
          bRet = true ;
          break ;
        }
    
      } while (_PASSING_) ;
    
      return bRet ;
    }
    
    //NOTE: Usually used for parameters, not for identifier in slot
    static bool findIdentifierInStmt( const Stmt *pStmt, const IdentifierInfo *pInfo )
    {
      bool bRet = false ;
    
      do
      {
        if ( !pStmt || !pInfo )
        {
          break ;
        }

    // probably not a good idea why it is commented out.
    //    if ( const DeclStmt *pDeclStmt = dyn_cast< DeclStmt >(pStmt) ) 
    //    {
    //      bRet = findIdentifierInDeclStmt( pDeclStmt, pInfo ) ;
    //      break ;
    //    }
   
        //TODO: Add feature for ObjCMessageExpr, use it's parameters

        if ( const DeclRefExpr *pDeclExpr = dyn_cast< DeclRefExpr >(pStmt) )
        {
          bRet = findIdentifierInDeclRef( pDeclExpr, pInfo ) ;
          break ;
        }
    
        int iCtr = 0 ;
    
        for ( Stmt::const_child_iterator pItem = pStmt -> child_begin(),
                pEndItem = pStmt -> child_end();
              pItem != pEndItem;
              pItem++, iCtr++ )
        {
          // MSEC_INN_DEBUG("\nredwud: ", "Dumping child #: " << iCtr << "name " << pItem ->getStmtClassName()  <<  "\n" ) ;
          const Stmt *pSourceExpr = *pItem ;
    
          if ( pSourceExpr && (isa <OpaqueValueExpr> (pSourceExpr)) )
          {
            pSourceExpr = dyn_cast<OpaqueValueExpr> (pSourceExpr) ->getSourceExpr() ;
          }
    
          if ( findIdentifierInStmt( pSourceExpr, pInfo ) )
          {
            bRet = true ;
            break ;
          }
        }
      } while (_PASSING_) ;
    
      return bRet ;
    }

    static const ObjCInterfaceDecl *isSupportedProtocol( const ObjCMethodDecl *pMD, IdentifierInfo *pInfo )
    {
      const ObjCInterfaceDecl *pRet = NULL ;

      do
      {
        if ( !pMD || !pInfo )
        {
          break ;
        }
         
        pRet = isSupportedProtocol( pMD ->getClassInterface(), pInfo ) ;

      } while (_PASSING_) ;

      return pRet ;
    }

    static const ObjCInterfaceDecl *isSupportedProtocol( const ObjCInterfaceDecl *pIfDecl, IdentifierInfo *pInfo )
    {
      const ObjCInterfaceDecl *pRet = NULL ;
    
      do
      {
        if ( !pIfDecl || !pInfo )
        {
          MSEC_INN_DEBUG( "redwud: ", "!pIfDecl" ) ;
          break ;
        }
        
        for ( ObjCInterfaceDecl::protocol_iterator pItem = pIfDecl ->protocol_begin(),
                pEndItem = pIfDecl ->protocol_end();
                pItem != pEndItem;
                pItem++ )
        {
          if ( pInfo == (*pItem) ->getIdentifier() )
          {
            pRet = pIfDecl ;
            break ;
          }
        }
      } while (_PASSING_) ;
    
      return pRet ;
    }

    static void getStrFromSL( StringRef &rszRet, const ObjCStringLiteral *pOCSL ) 
    {
      do
      {
          const StringLiteral *pSL = pOCSL ->getString() ;

          if ( !pSL )
          {
            MSEC_INN_DEBUG( "redwud: ", "!pSL !!!\n" ) ;
            break ;
          }

          rszRet = pSL ->getString() ;
    
      } while (_PASSING_) ;
    }

//#define MSEC_DBG 1

    static void getStrFromExpr( StringRef &rszRet, const Expr *pExpr, StringRef *pIdName = NULL ) 
    {
      MSEC_INN_DEBUG_FUNC( "redwud: ", "ENTER /////////" ) ;

      do
      {
        if ( !pExpr )
        {
          break ;
        }

        MSEC_INN_DEBUG( "redwud: ", "Dumping pExpr\n" ) ;
        //pExpr ->dumpColor() ;


        MSEC_INN_DEBUG( "redwud: ", "futuristic trouble !!!\n" ) ;
        //FIXME: Make this really nice, seems that this will create trouble in the future
        if ( const ObjCStringLiteral *pOCSL = dyn_cast <ObjCStringLiteral> ( pExpr ) )
        {
          getStrFromSL( rszRet, pOCSL ) ;
          break ;
        }

        MSEC_INN_DEBUG( "redwud: ", "pre casting ObjCMessageExpr !!!\n" ) ;
        // FIXME: This is just a work-around for a NSString passed with stringWithFormat, others may explode as well.
        if ( const ObjCMessageExpr *pMsg = dyn_cast <ObjCMessageExpr> (pExpr) )
        {
          if ( !(pMsg ->getNumArgs()) )
          {
            break ;
          }

          const Expr *pArg = pMsg ->getArg(0) ;

          if ( !pArg )
          {
             break ;
          }

          MSEC_INN_DEBUG( "redwud: ", "pre casting ObjCStringLiteral !!!\n" ) ;
          const ObjCStringLiteral *pOCSL = dyn_cast <ObjCStringLiteral> ( pArg ) ;

          if ( !pOCSL )
          {
            //MSEC_INN_DEBUG( "redwud: ", "but no win !!!\n" ) ;
            break ;
          }

          getStrFromSL( rszRet, pOCSL ) ;
          break ;
        }

        //TODO: Consider this on intial check, but temporarily do this checking at this point
        if ( isa <PredefinedExpr> (pExpr) )
        {
          MSEC_INN_DEBUG( "redwud: ", "PredefineExpr\n" ) ;
          break ;
        }

        //if ( !isa <const DeclRefExpr> (pExpr) )
        //{
        //  MSEC_INN_DEBUG( "redwud: ", "!DeclRefExpr\n" ) ;
        //  break ;
        //}
        
        MSEC_INN_DEBUG( "redwud: ", "Pre casting DeclRefExpr !!!\n" ) ;
        if ( const DeclRefExpr *pDeclRef = dyn_cast <DeclRefExpr> (pExpr) )
        {
          MSEC_INN_DEBUG( "redwud: ", "pre pDeclRef ->getDecl() !!!\n" ) ;
          const ValueDecl *pValueDecl = pDeclRef ->getDecl() ;

          MSEC_INN_DEBUG( "redwud: ", "post pDeclRef ->getDecl() !!!\n" ) ;
          if ( !pValueDecl )
          {
            break ;
          }

          MSEC_INN_DEBUG( "redwud: ", "Pre casting VarDecl !!!\n" ) ;
          const VarDecl *pVarDecl = dyn_cast <VarDecl> (pValueDecl) ;

          if ( !pVarDecl )
          {
            break ;
          }

          do
          {
             //Fill in pIdName if it has been set 
             if ( !pIdName )
             {
               break ;
             }
           
             //FIXME: Decide whether to include all the referenced names or just the immediate name
             //       ObjC objects can be passed around thus it is possible to mind those names.

             // Already been assigned sometime along the way
             if ( !(pIdName ->empty()) )
             {
               break ;
             }

             IdentifierInfo *pInfo = pVarDecl ->getIdentifier() ;

             if ( !pInfo )
             {
               //MSEC_INN_DEBUG( "redwud: ", "!pInfo !!!\n" ) ;
               break ;
             } 

             *pIdName = pInfo ->getName() ;
             //MSEC_INN_DEBUG( "redwud: ", "Name found!"  << *pIdName <<  "!\n" ) ;

          } while (_PASSING_) ;

          const Expr *pAnyInit = pVarDecl ->getAnyInitializer() ;

          if ( !pAnyInit )
          {
            break ;
          }
          
          const ObjCStringLiteral *pOCSL = dyn_cast <ObjCStringLiteral> ( pAnyInit ) ;

          if ( !pOCSL )
          {
            MSEC_INN_DEBUG( "redwud: ", "recursing !!!\n" ) ;
            getStrFromExpr( rszRet, pAnyInit, pIdName ) ; 
            break ;
          }
        
          getStrFromSL( rszRet, pOCSL ) ;
          break ;
        }

        MSEC_INN_DEBUG( "redwud: ", "isa <IntegerLiteral> (pExpr)\n" ) ;
        if ( isa <IntegerLiteral> (pExpr) )
        {
          // Not a string after all
          //MSEC_INN_DEBUG( "redwud: ", "!String !!!\n" ) ;
          break ;
        }

        MSEC_INN_DEBUG( "redwud: ", "recursing !!!\n" ) ;

        Expr::const_child_iterator piChild = pExpr ->child_begin() ;

        if ( pExpr ->child_end() == piChild )
        {
          MSEC_INN_DEBUG( "redwud: ", "last child !!!\n" ) ;
          break ;
        }

        getStrFromExpr( rszRet, dyn_cast <Expr> (*(piChild)), pIdName ) ;        

      } while (_PASSING_) ;

      MSEC_INN_DEBUG_FUNC("redwud:","EXIT /////////") ;
    } // End of getStrFromExpr() ;

    // Only checks for the first of every child, parameter, etc
    // Returns true if found, else false
    static bool getInnerBool( const Stmt *pStmt, bool &rbValue )
    {
      bool bFound = false ;
    
      do
      {
        if ( !pStmt )
        {
          break ;
        }

        if ( const ObjCMessageExpr *pMsgExpr = dyn_cast< ObjCMessageExpr >(pStmt) )
        {
          if ( const ObjCBoolLiteralExpr *pBoolExpr = 
                 dyn_cast< ObjCBoolLiteralExpr >( pMsgExpr ->getArg(0) ) )
          {
            rbValue = pBoolExpr ->getValue() ;   
            bFound  = true ;
          }
          
          break ;
        }
    
        int iCtr = 0 ;
    
        for ( Stmt::const_child_iterator pItem = pStmt -> child_begin(),
                pEndItem = pStmt -> child_end();
              pItem != pEndItem;
              pItem++, iCtr++ )
        {
          // MSEC_INN_DEBUG("\nredwud: ", "Dumping child #: " << iCtr << "name " << pItem ->getStmtClassName()  <<  "\n" ) ;
          const Stmt *pSourceExpr = *pItem ;
    
          if ( pSourceExpr && (isa <OpaqueValueExpr> (pSourceExpr)) )
          {
            pSourceExpr = dyn_cast<OpaqueValueExpr> (pSourceExpr) ->getSourceExpr() ;
          }
   
          // Already found 
          if ( getInnerBool( pSourceExpr, rbValue ) )
          {
            bFound = true ;
            break ;
          }
        }
      } while (_PASSING_) ;
    
      return bFound ;
    }

    static const Expr *getParamExpr( const Expr *pExpr, unsigned iParam )
    {
      const Expr *pRet = NULL ;
      unsigned iCtr = 0 ;

      for ( Stmt::const_child_iterator pItem = pExpr -> child_begin(),
              pEndItem = pExpr -> child_end() ;
            pItem != pEndItem ;
            pItem++, iCtr++ )
      {
        if ( iCtr == iParam )
        {
          pRet = dyn_cast<Expr> ( *pItem ) ;
          break ;
        }
      }

      return pRet ;
    }
  } ; //CMSecCommon

  /////////////////////////////////////////////////////
  struct SMSecState
  {
  protected:
    enum eSecurityStat { Secure, NotSecure } m_SecStat ;
 
    //redwud: Copy Constructor, controls the state to Secure/NotSecure
    //        that is why it is under private, limits the creation 
    //        to getSecure() and getNotSecure()
    SMSecState(eSecurityStat InK) : m_SecStat(InK) { }
  
  public:
    bool isSecure() const    { return m_SecStat == Secure; }
    bool isNotSecure() const { return m_SecStat == NotSecure; }
    
    static SMSecState getSecure()    { return SMSecState(Secure); }
    static SMSecState getNotSecure() { return SMSecState(NotSecure); }
    
    virtual bool operator==(const SMSecState &X) const
    {
      return m_SecStat == X.m_SecStat;
    } 

    //redwud: Just add m_SecStat to ID
    //redwud: This seems to be common among building blocks of llvm/clang
    void Profile(llvm::FoldingSetNodeID &ID) const
    {
      ID.AddInteger( m_SecStat );
    }
  } ;

} //



#endif /* MSEC_COMMON_H */
