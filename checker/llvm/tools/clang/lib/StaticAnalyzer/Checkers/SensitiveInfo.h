//
//
//  Created by Pedraita, Raymund on 1/31/14.
//
#include <string>
#include <fstream>
#include <iostream>
#include <wordexp.h>

#include "llvm/Support/Regex.h"

#define MSEC_DBG
#include "clang/StaticAnalyzer/Core/MSecCommon.h"
//////////////////////////////////////////////////////////////////////////////////////

//	    	    "(confidential|name|developer|programmer|token|(trade\\s*|)secret)"
//	    	  , "pass((w(or|)d)|)"
//	    	  , "us(e|)r((name|id)|)"
//	    	  , "credit(\\s*?card(\\s*?n(o(\\.|)|um(ber|))|)|)"
//	    	  , "((dev(ice|)member|student|employee|biometric)\\s*?|)[^\\(]\\s*?id(entification|)"

//	    	  , "(expir(y|ation)|birth)\\s*(day|date|)"
//	    	  , "(ip|internet\\s*(protocol|)|)(e(lectronic|\\-|)\\s*mail|)\\s*?(addr(ess|)|)"

//	    	  , "contact\\s*(info(rmation|)|)"
//	    	  , "(b(a|)nk|rec(ord|)|bal(ance|)|rat(e|ing))"
//	    	  , "(ACH|acc(ou|)nt|serial|fax|pp|pas*p(|o)rt)(\\s*?n(o(\\.|)|um(ber|))|)"
//	    	  , "(visa\\s*|)(code|)"
//	    	  , "(grade|pay|salary|financ(e|ial))\\s*(info(rmation|)|)"
//	    	  , "(ss|soc(ial|)\\s*sec(urity|))(\\s*?n(o(\\.|)|um(ber|))|)"
//	    	  , "(arc|alien|resident)\\s*(card(\\s*?n(o(\\.|)|um(ber|))|)|)"
//	    	  , "(driver\\'s\\s*license|asset|liability|intellectual\\s*property)"
//	    	  , "(firewall\\s*|)(conf|(iguration|)|)"

// Since the checker will not have a persistent controller or something, this class should
// be taking in-charge on its own. Manages all keywords and should be a singleton because
// there should be one instance of this class for entire checkers, since sensitive information
// should be uniform.

// Warning: It seems that in POSIX Regex there is no non-greedy match e.g. *?, we will strip
//          this implementation for the moment because it will cause a non match. FIXME will be
//          adding support for that in the future.
//          NOTE: Temporary work around for this is to wrap the the preceeding xx* with () e.g. \\s*? -> (\\s*)?
namespace msec_cmn 
{
  class CSensitiveInfo
  {
  private:
    std::string m_szKeywords ; //Keywords or patterns combined with | 
  
    // Default constructor
    CSensitiveInfo()
    {
        
    }
    
    ~CSensitiveInfo()
    {
        
    }

  public:
    static CSensitiveInfo &create()
    {
      static CSensitiveInfo thisInfo ;
      static bool bCreated = false ;

      do
      {

        if ( bCreated )
        {
          MSEC_DEBUG( "redwud: ", "already created! \n" ) ;
          break ;
        }

        // std::string szKeywords[] = 
        // {
        //     "confidential|name|developer|programmer|token|(trade\\s*)*secret"
	    	//   , "pass((w(or)*d))*"
        //   , "us(e)*r((name|id))*"
	    	//   , "credit((\\s*)?card((\\s*)?n(o(\\.)*|um(ber)*))*)*"
	    	//   , "((dev(ice)*member|student|employee|biometric)(\\s*)?)*[^\\(](\\s*)?id(entification)*"
        //   , "(expir(y|ation)|birth)\\s*(day|date)*"
	    	//   , "(ip|internet\\s*(protocol)*)|(e(lectronic|\\-)\\s*mail)|((\\s*)?addr(ess)*)"
        //   , "contact\\s*(info(rmation)*)*"
	    	//   , "(b(a)*nk|rec(ord)*|bal(ance)*(\\s*)?|rat(e|ing))"
	    	//   , "(ACH|acc(ou)*nt|serial|fax|pp|pas*po*rt)((\\s*)?n(o(\\.)*|um(ber)*))*"
	    	//   , "(visa\\s*)(code)*|(code)"
        //   , "(grade|pay|salary|financ(e|ial))\\s*(info(rmation)*)*"
	    	//   , "(ss|soc(ial)*\\s*sec(urity)*)((\\s*)?n(o(\\.)*|um(ber)*))*"
        //   , "(arc|alien|resident)\\s*(card((\\s*)?n(o(\\.)*|um(ber)*))*)*"
        //   , "(driver\\'s\\s*license|asset|liability|intellectual\\s*property)"
	    	//   , "(firewall\\s*)+(conf(iguration)*)*|(conf(iguration)*)"

        // } ;
      
        // for ( int iCtr = 0; iCtr < _countof( szKeywords ); iCtr++ )
        // {
        // //   thisInfo.addKeyword( szKeywords[ iCtr ] ) ;
        // }

        const char *szSensiRegExPath = "~/Applications/XSecurity/SensitiveInfo.txt" ;
        wordexp_t aggWord ;
        char      **ppExpandedPath ;
        
        wordexp( szSensiRegExPath, &aggWord, 0 ) ;
        ppExpandedPath = aggWord.we_wordv ;
        
        if ( !ppExpandedPath || !(*ppExpandedPath) )
        {
          break ;
        }
        
        std::string szKeyword ;
        std::ifstream fSensitive( *ppExpandedPath ) ;
        
        if ( !fSensitive.is_open() )
        {
          MSEC_DEBUG( "redwud: ", "not open!!!" << "bad: " << fSensitive.bad() << "fail: " << fSensitive.fail() << "good:" << fSensitive.good() << szSensiRegExPath << "\n" ) ;
          break ;
        }
        
        wordfree( &aggWord ) ;
        const char chComment = '#' ;

        MSEC_DEBUG( "redwud: ", "creating new sensitive info!!! \n" ) ;
        while ( std::getline( fSensitive, szKeyword ) )
        {
          //MSEC_DEBUG( "redwud: ", "first char: " << szKeyword << "\n" ) ;
          // Skip empty lines, this will allow visual grouping
          if ( szKeyword.empty() )
          {
            continue ;
          }

          // Comment:
          // Temporariy check the first character if it is '#'
          // TODO: Make it # aware
          if ( *szKeyword.begin() == chComment )
          {
            continue ;
          }

          thisInfo.addKeyword( szKeyword ) ;
          szKeyword.clear() ;
        }

        // Regardless whether thisInfo has valid keywords or not, it is created at this point
        bCreated = true ;
      
        MSEC_DEBUG( "redwud: ", "keywords: " << thisInfo.getKeywords() << "\n" ) ;
      } while (_PASSING_) ;
      
      return thisInfo ;
    } // end of static create()

    //TODO: Consider removing this, if not necessary
    std::string getKeywords()
    {
      return m_szKeywords ;
    }

    void addKeyword( std::string szKeyword )
    {
      if ( !m_szKeywords.empty() )
      {
        m_szKeywords.append("|") ;
      }
     
      szKeyword = std::string( "(" ) + szKeyword + std::string( ")" ) ;

      m_szKeywords.append( szKeyword ) ;
    }
    
    bool isSensitive( std::string szTarget )
    {
      bool bRet = false ;
     
      //MSEC_DEBUG( "redwud: ", "keywords: " << getKeywords() << "\n" ) ;
      do
      {
        if ( szTarget.empty() )
        {
          break ;
        }
        
        //TODO: Consider adding other flags 
        llvm::Regex regEngine( getKeywords(), llvm::Regex::IgnoreCase  ) ;

        bRet = regEngine.match( szTarget ) ; 
      } while(_PASSING_) ;
    
      return bRet ;
    }

  } ; // CSensitiveInfo

} 

