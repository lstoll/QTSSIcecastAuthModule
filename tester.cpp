
#include <string.h>


#include <string.h>

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <string.h>

main()
{
    // todo - need to check string lengths before allocating, else i'm open for buffer overflow. check this.
    char username[255];
    bool usernameset = false;
    char password[255];
    bool passwordset = false;
    
    char* theRequestedURL = "DESCRIBE rtsp://ubuntu32/sample_100kbit.mp4?u=username&p=password RTSP/1.0\nCSeq: 1\nAccept: application/sdp\nBandwidth: 384000\nAccept-Language: en-US\nUser-Agent: QuickTime/7.5 (qtver=7.5;cpu=IA32;os=Mac 10.5.3)\n\n\n";
    
    if(index(theRequestedURL, '?')){ 
        char buf[512]; 
        snprintf(buf, 512, theRequestedURL);
        
        char* queryString;
        
        char* progress1;
        
        // split off everything after the first line, we don't need it.
        queryString = ::strtok_r(buf, "\n", &progress1); 
        // split around the ?, ignore the first part
        ::strtok_r(buf, "?", &progress1); 
        // get the second part of the previous split
        queryString = ::strtok_r(NULL, "?", &progress1); 
        // split working around the space
        queryString = ::strtok_r(queryString, " ", &progress1);
        printf("queryString: %s\n", queryString);
        // we should now have our url
        
        char* tmp = strtok(queryString, "=&");
        
        int iters;
    
        for (iters=0; (tmp != NULL); iters++)
        {    
            char name[255]; // I'm asking for a buffer overflow, aren't I? TODO - check this.
            if ((iters % 2) != 1) {
                // even - its a name. this will always be 'first'
                strcpy(name, tmp);
                printf("name: %s\n", tmp);
            }
            else {
                // non-even, its a value. this will always come second
                printf("value: %s\n", tmp);
                
                if (strcmp(name, "u") == 0) {
                    // this value is the username
                    printf("name is currently: %s. username being set to %s\n", name, tmp);
                    strcpy(username, tmp);
                    usernameset = true;
                }
                else if (strcmp(name, "p") == 0) {
                    // this value is the username
                    printf("name is currently: %s. password being set to %s\n", name, tmp);
                    strcpy(password, tmp);
                    passwordset = true;
                }
                
            }
            tmp = strtok(NULL, "=&");
        }
        
        printf("username: %s, password: %s\n\n", username, password);
        
        if (!usernameset || !passwordset) {
            printf("username or password not set.");
        }

        
        
//        working = ::strtok(NULL, "="); 
//        printf("working: %s\n", working);
//        
//        char *paramstok = strtok_r(working, "=", &progress1);
//
//        while (paramstok) {
//            printf("%s\n", paramstok);
//            strtok_r(NULL, "&", &progress1);
//            paramstok = strtok_r(NULL, "=", &progress1);
////            printf("tok1: %s\n", paramstok);
////            printf("tok2: %s\n", strtok_r(NULL, "=", &progress1));
//        }
    

        
        
        //printf("username: %s", username);
                          
//        if(authScheme == qtssAuthShib && ! ::strcmp(sessionkey, "shib")) { 
//            sessionkey = ::strtok(NULL, " "); 
//        } 
//        else if(authScheme == qtssAuthModu && ! ::strcmp(sessionkey, "sess")) { 
//            sessionkey = ::strtok(NULL, " "); 
//        } 
//        else { 
//            // we arent supposed to return errors here - but lets test it.
//            qtss_printf("QTSSIcecastAuthModule::RTSPFilter: request failed, returning QTSS_RequestFailed");
//            theErr = QTSS_RequestFailed; 
//        } 
    }
    else {
        std::cout << "no match!";
    }
    
    
    printf("\n\n\n");
    
    
//    cout << "Hello World!";
//    return 0;
}