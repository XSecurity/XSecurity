//
//  CBufferOverflow.m
//  CLangTest
//
//  Created by Pedraita, Raymund on 10/1/14.
//  Copyright (c) 2014 XSecurity. All rights reserved.
//

#import "CBufferOverflow.h"
#include <stdio.h>


@implementation CBufferOverflow



- (bool) grantAccess: (const char *)szUser
{
    return true ;
}

- (void) privilegedAction
{

}

// - (int) gets_sample
// {
//     char username[8] ;
//     int allow = 0 ;
//     printf("Enter your username, please: ") ;
//     
//     gets(username); // user inputs "malicious"
// 
//     if ( [ self grantAccess: username ] )
//     {
//         allow = 1;
//     }
//     
//     if (allow != 0)
//     {
//         // has been overwritten by the overflow of the username.
//         [ self privilegedAction ] ;
//     }
//     
//     fgets( username, 5,  stdin) ;
//     
//     return 0;
// }
// 
// 

// - (int) strcpy_variant_sample
// {
// 
//     char szOldUserName[20] = "yo user!" ;
//     const char szNewUserName[20] = "yeee! user!" ;
//     
//     strcpy( szOldUserName, szNewUserName ) ;
//     
//     printf( "%s", szOldUserName ) ;
//     
//     strncpy( szOldUserName, "12345",  5 ) ;
//     
//  
//     return 0 ;
// }


enum { BUFFER_SIZE = 10 };

- (int) sprintf_variant_sample: (const char *) format, ... 
{
    char buffer[BUFFER_SIZE];
//    int check = 0;
    
    sprintf(buffer, "%s", "This string is too long!");
//    
//    sprintf(buffer, "%i %s", 100, "This string is too long!");

    va_list args;

    va_start (args, format);
    
    vsprintf (buffer,format, args);
    perror (buffer);
    
    va_end (args);

    return EXIT_SUCCESS;
}




@end
