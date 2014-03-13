//
//  CInstance.h
//  XSecurity
//
//  Created by Pedraita, Raymund on 1/5/14.
//  Copyright (c) 2014 XSecurity Project. All rights reserved.
//

#import <Foundation/Foundation.h>


// This is just a data structure, but occationally might need
// some methods/messages thus using an object instead.
@interface CInstance : NSObject
{
    
}

@property (readonly, getter = getClass)   NSString *m_szClass ;

- (id)initWithClass: (NSString *)szClass ;
- (void) dealloc ;

@end

//////////////////////////////////////////////////////////////////////////////////////

@interface CKeywordInstance : CInstance
{
    
}

@property (readonly, getter = getMethods) NSArray  *m_aszMethods ;
@property (readonly, getter = getArgs)    NSArray  *m_aszArgs ;

- (id) initWithClass: (NSString *) szClass withMethods: (NSArray *) aszMethods withArgs: (NSArray *) aszArgs ;
- (void) dealloc ;

@end

//////////////////////////////////////////////////////////////////////////////////////

// This guy is late in the game but it should be first but it is too late
// Having classes, methods and args is the default fields of keyword

// There is a bit of a twist from the expected here, it is inherited from CInstance
// due to replication of unnecessary properties. e.g. m_aszMethods, and m_aszArgs
// though in the plist those Arrays are still present
@interface CPureKeywordInstance : CInstance
{
    
}

// Note: This looks that it needs getMethods() and getArgs() but don't be decieved
//       coz all of them are treated as keywords

@property (readonly, getter = getKeywords) NSArray  *m_aszKeywords ;

- (id)initWithClass:(NSString *)szClass withKeywords: (NSArray *)aszKeywords ;
- (void) dealloc ;
@end


//////////////////////////////////////////////////////////////////////////////////////

@interface CKeywordCalleeInstance : CInstance
{
    
}

//m_dicMethods points to plist's Instances -> [ClassName] -> Methods
@property (readonly, getter = getDicMethods) NSDictionary  *m_dicMethods ;

- (NSArray *)getKeywordsFromDictionary: (NSDictionary *) dicMethod ;
- (id)initWithClass:(NSString *)szClass withDicMethods: (NSDictionary *)dicMethods ;
- (void) dealloc ;

@end


//////////////////////////////////////////////////////////////////////////////////////

@interface CKeywordSensitiveInstance : CKeywordInstance
{
    
}

@property (readonly, getter = getFunctions) NSArray  *m_aszFunctions ;

- (id)initWithClass:(NSString *)szClass withMethods: (NSArray *) aszMethods withArgs: (NSArray *) aszArgs withFunctions: (NSArray *)aszFunctions ;
- (void) dealloc ;

@end



