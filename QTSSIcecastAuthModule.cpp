/*
 * Copyright (c) 2009 Lincoln Stoll.  All Rights Reserved.
 */
/*
    File:       QTSSIcecastAuthModule.cpp
				
                Example of preferences allowing only connections from loopback (or any address in the 127.0.0.X network):
                <MODULE NAME="QTSSIcecastAuthModule" >
                    <PREF NAME="enabled" TYPE="Bool16" >true</PREF>
                    <PREF NAME="IPBypassList">127.0.0.*</PREF>
                    <PREF NAME="StartSessionEndpoint">http://server/stream_auth/start_session</PREF>
                    <PREF NAME="EndSessionEndpoint">http://server/stream_auth/end_session</PREF>
                </MODULE>
*/

#include "QTSSIcecastAuthModule.h"
#include "defaultPaths.h"
#include "StrPtrLen.h"
#include "OSArrayObjectDeleter.h"
#include "SafeStdLib.h"
#include "QTSSMemoryDeleter.h"
#include "StringParser.h"
#include "OSMemory.h"
#include "QTSSModuleUtils.h"

#include <curl/curl.h>

// STATIC DATA
static QTSS_ServerObject        sServer         = NULL;
static QTSS_ModuleObject        sModule         = NULL;
static QTSS_ModulePrefsObject	sModulePrefs    = NULL;

const UInt32 kBuffLen = 512;

// Module description and version
static char*            sDescription        = "QTSS Icecast Authorization module";
static UInt32           sVersion            = 0x00010000;

// FUNCTION PROTOTYPES

static QTSS_Error QTSSIcecastAuthModuleDispatch(QTSS_Role inRole, QTSS_RoleParamPtr inParams);
static QTSS_Error Register();
static QTSS_Error Initialize(QTSS_Initialize_Params* inParams);
static QTSS_Error Shutdown();
static QTSS_Error RereadPrefs();
static QTSS_Error Authenticate();
//static QTSS_Error Authorize(QTSS_StandardRTSP_Params* inParams);
static Bool16 AcceptSession(QTSS_RTSPSessionObject inRTSPSession, QTSS_RTSPRequestObject inRTSPRequest);
static QTSS_Error RTSPPreProcess(QTSS_StandardRTSP_Params* inParams);
static QTSS_Error RTSPFilter(QTSS_StandardRTSP_Params* inParams);
static QTSS_Error ClientSessionClosing(QTSS_ClientSessionClosing_Params* inParams);
static QTSS_Error SendErrorResponseWithMessage( QTSS_RTSPRequestObject inRequest, QTSS_RTSPStatusCode inStatusCode, StrPtrLen* inErrorMessagePtr);
// printing errors
void PrintQTSSError(const char msgPrefix[], const char msgSuffix[], QTSS_Error theErr);
static Bool16 IsRTSPSessionAuthenticated(QTSS_RTSPSessionObject* theRTSPSession);
static Bool16 IsClientInBypassList(QTSS_RTSPSessionObject* theRTSPSession);
static Bool16 IsRequestMethodBypassable(QTSS_RTSPRequestObject* theRTSPRequest);
// methods to perform the HTTP auth
static Bool16 CallAuthorizeSession(QTSS_ClientSessionObject* theClientSession, QTSS_RTSPSessionObject* theRTSPSession,
        QTSS_RTSPRequestObject* theRTSPRequest, char* username, char* password);
static void CallEndSession(QTSS_ClientSessionObject* theClientSession);

// Module preferences and their defaults
static Bool16               sEnabled                = false;
static Bool16               kDefaultEnabled         = false;
static char*                sIPBypassList           = NULL;
static QTSS_AttributeID     sIPBypassListID         = qtssIllegalAttrID;
static char*                sStartSessionEndpoint   = NULL;
static char*                sEndSessionEndpoint     = NULL;

// Other info
static char hostname[128];

// Attribute IDs
static QTSS_AttributeID attrRtspSessionProvidedUsername = qtssIllegalAttrID;
static QTSS_AttributeID attrRtspSessionProvidedPassword = qtssIllegalAttrID;
static QTSS_AttributeID attrRtspSessionAuthenticated = qtssIllegalAttrID;
static QTSS_AttributeID attrClientSessionFullSessionID = qtssIllegalAttrID;
static QTSS_AttributeID attrClientSessionMountPoint = qtssIllegalAttrID;

// FUNCTION IMPLEMENTATIONS

QTSS_Error QTSSIcecastAuthModule_Main(void* inPrivateArgs)
{
	//qtss_printf("IN MODULE MAIN\n");
	return _stublibrary_main(inPrivateArgs, QTSSIcecastAuthModuleDispatch);
}

QTSS_Error QTSSIcecastAuthModuleDispatch(QTSS_Role inRole, QTSS_RoleParamPtr inParams) {
    switch (inRole) {
        case QTSS_Register_Role:
            return Register();
        case QTSS_Initialize_Role:
            return Initialize(&inParams->initParams);
        case QTSS_RereadPrefs_Role:
            return RereadPrefs();
//        case QTSS_RTSPAuthenticate_Role:
//            return Authenticate();
//        case QTSS_RTSPAuthorize_Role:
//            return Authorize(&inParams->rtspRequestParams);
        case QTSS_Shutdown_Role:
            return Shutdown();
        case QTSS_RTSPPreProcessor_Role:
            if (sEnabled) return RTSPPreProcess(&inParams->rtspRequestParams);
            else return QTSS_NoErr;
        case QTSS_RTSPFilter_Role:
            //RereadPrefs();
            if (sEnabled) return RTSPFilter(&inParams->rtspRequestParams);
            else return QTSS_NoErr;
        case QTSS_ClientSessionClosing_Role:
            if (sEnabled) return ClientSessionClosing(&inParams->clientSessionClosingParams);
            else return QTSS_NoErr;
    }
    return QTSS_NoErr;
}


QTSS_Error Register()
{
    QTSS_Error theErr;
    // Do role & attribute setup
    // for when the server starts
    theErr = QTSS_AddRole(QTSS_Initialize_Role);
    //PrintQTSSError("QTSSIcecastAuthModule::Register", "register for initialize role", theErr);
    // for when asked to re-read the prefs file
    
    qtss_printf("QTSSIcecastAuthModule::Register about to register for reread prefs role\n");
    (void)QTSS_AddRole(QTSS_RereadPrefs_Role);
    qtss_printf("QTSSIcecastAuthModule::Register after register for reread prefs role, about to register for filter\n");
    
    // can't find doc on these - apparently deprecated as of v3??
    //(void)QTSS_AddRole(QTSS_RTSPAuthenticate_Role);
    //(void)QTSS_AddRole(QTSS_RTSPAuthorize_Role);
    
    // the earliest call on a RTSP request - needed to get the full query including
    // query params.
    (void)QTSS_AddRole(QTSS_RTSPFilter_Role);

    // called to pre-process a RTSP request - has full client info, including timestamp
    // for completely unique session ID's (rather then the increment)
    (void)QTSS_AddRole(QTSS_RTSPPreProcessor_Role);
    
    // the shutdown role, for cleanup stuff
    (void)QTSS_AddRole(QTSS_Shutdown_Role);
    
    // The client close role, to send the end message
    (void)QTSS_AddRole(QTSS_ClientSessionClosing_Role);
    
    qtss_printf("QTSSIcecastAuthModule::Register all roles registered, about to register attributes\n");
    
    // add the attribute to hold the username when provided
    (void)QTSS_AddStaticAttribute(qtssRTSPSessionObjectType,
                            "ProvidedUsername", NULL, qtssAttrDataTypeCharArray);
    (void)QTSS_IDForAttr(qtssRTSPSessionObjectType, "ProvidedUsername",  &attrRtspSessionProvidedUsername);
    // add the attribute to hold the username when provided
    (void)QTSS_AddStaticAttribute(qtssRTSPSessionObjectType,
                            "ProvidedPassword", NULL, qtssAttrDataTypeCharArray);
    (void)QTSS_IDForAttr(qtssRTSPSessionObjectType, "ProvidedPassword",  &attrRtspSessionProvidedPassword);
    // add the attribute that holds the flag to show if the session has been authenticated
    // we check this first, if the session is authenticated we can skip everything
    theErr = QTSS_AddStaticAttribute(qtssRTSPSessionObjectType,
                            "SessionAuthenticated", NULL, qtssAttrDataTypeBool16);
    //PrintQTSSError("QTSSIcecastAuthModule::Register", "add session authenticated attribute to rtsp session", theErr);
    theErr = QTSS_IDForAttr(qtssRTSPSessionObjectType, "SessionAuthenticated",  &attrRtspSessionAuthenticated);
    //PrintQTSSError("QTSSIcecastAuthModule::Register", "get ID for session authenticated attribute on rtsp session", theErr);
    // add to hold the 'full' session ID on the RTSP Session (start time millis CONCAT sever session id, to ensure uniqueness)
    (void)QTSS_AddStaticAttribute(qtssClientSessionObjectType,
                            "FullSessionID", NULL, qtssAttrDataTypeCharArray);
    (void)QTSS_IDForAttr(qtssClientSessionObjectType, "FullSessionID",  &attrClientSessionFullSessionID);
    
    // the mount point needs to be stashed in the client session, for reporting on teardown
    (void)QTSS_AddStaticAttribute(qtssClientSessionObjectType,
                            "MountPoint", NULL, qtssAttrDataTypeCharArray);
    (void)QTSS_IDForAttr(qtssClientSessionObjectType, "MountPoint",  &attrClientSessionMountPoint);
    
    
    qtss_printf("QTSSIcecastAuthModule::Register end of method\n");
    return QTSS_NoErr; // need to return. should do something with any errors captured above.
}


QTSS_Error Initialize(QTSS_Initialize_Params* inParams)
{

    // Setup module utils
    QTSSModuleUtils::Initialize(inParams->inMessages, inParams->inServer, inParams->inErrorLogStream);

    // Get the server object
    sServer = inParams->inServer;
    
    // Get our prefs object
    sModule = inParams->inModule;
    sModulePrefs = QTSSModuleUtils::GetModulePrefsObject(sModule);

    // Set our version and description
    (void)QTSS_SetValue(sModule, qtssModDesc, 0, sDescription, ::strlen(sDescription));   
    (void)QTSS_SetValue(sModule, qtssModVersion, 0, &sVersion, sizeof(sVersion)); 
    
    // get the hostname
    gethostname(hostname, sizeof hostname);
    qtss_printf("QTSSIcecastAuthModule::Initialize hostname is %s\n", hostname);

    RereadPrefs();
    return QTSS_NoErr;
}

QTSS_Error Shutdown()
{
    return QTSS_NoErr;
}

QTSS_Error RereadPrefs()
{	
    qtss_printf("QTSSIcecastAuthModule::RereadPrefs method start\n");
    QTSSModuleUtils::GetAttribute(sModulePrefs, "enabled", qtssAttrDataTypeBool16, 
        &sEnabled, &kDefaultEnabled, sizeof(sEnabled));
    
    //const char* sIPBypassListDefault = "127.0.0.*";
    
    //QTSSModuleUtils::GetAttribute(sModulePrefs, "IPBypassList", qtssAttrDataTypeCharArray, 
    //    &sIPBypassList, &sIPBypassListDefault, sizeof(sIPBypassListDefault));

    delete [] sIPBypassList;
    // this is done to init the pref if it doesn't already exist.
    sIPBypassList = QTSSModuleUtils::GetStringAttribute(sModulePrefs, "IPBypassList", "127.0.0.*");
    
    // this gets the ID - we search in this later.
    sIPBypassListID = QTSSModuleUtils::GetAttrID(sModulePrefs, "IPBypassList");
    
    // our notification endpoints
    sStartSessionEndpoint = QTSSModuleUtils::GetStringAttribute(sModulePrefs, "StartSessionEndpoint", "http://127.0.0.1/startsession");
    sEndSessionEndpoint = QTSSModuleUtils::GetStringAttribute(sModulePrefs, "EndSessionEndpoint", "http://127.0.0.1/endsession");
    
    if (sEnabled) qtss_printf("QTSSIcecastAuthModule enabled\n");
    else qtss_printf("QTSSIcecastAuthModule not enabled\n");
    
    qtss_printf("QTSSIcecastAuthModule::RereadPrefs method end, return noerr\n");
    return QTSS_NoErr;
}

// This is not necessary, but could be used to perform Authentication Role actions
QTSS_Error Authenticate()
{
    return QTSS_NoErr;
}

/*
 * This method is called because it is the only one that gets the full URL params, to capture
 * the username and password. We don't have access to the client session here, so save
 * the user and pass in the session for later. This is called BEFORE PostProcess
 */
QTSS_Error RTSPFilter(QTSS_StandardRTSP_Params* inParams) {
    QTSS_Error              theErr = QTSS_NoErr;
    QTSS_RTSPRequestObject  theRTSPRequest = inParams->inRTSPRequest;
    QTSS_RTSPSessionObject  theRTSPSession = inParams->inRTSPSession;
    
    // FAIL - can't do this here. need to finally move the auth to preprocess, and use this
    // just for param capture.
    // On the flip site, it seems that everything is really early here - if query params
    // don't work, can embed them in the URL path, extract here, and rewrite the URL in the request
    // and it should work fine. this could be handy if proxy's become an issue, because each request
    // would have a unique path.
    
//    // see if the method is bypassable. if it is, skip processing
//    qtss_printf("QTSSIcecastAuthModule::RTSPFilter: about to check if the method is bypassable\n");
//    if (IsRequestMethodBypassable(&theRTSPRequest)) return QTSS_NoErr;
    
    // see if the client is in the bypass list. if they are, skip all processing
    if (IsClientInBypassList(&theRTSPSession)) return QTSS_NoErr;
    
    // check to see if the session is already auth'd. If it is, skip processing
    if (IsRTSPSessionAuthenticated(&theRTSPSession)) {
        printf("QTSSIcecastAuthModule::RTSPFilter RTSP session is authenticated, do nothing.\n");
        return QTSS_NoErr; // we are authenticated, don't do anything
    }
    
    char* qtssRTSPSesIDString = NULL;
    (void) QTSS_GetValueAsString(theRTSPSession, qtssRTSPSesID, 0, &qtssRTSPSesIDString);
    printf("QTSSIcecastAuthModule::RTSPFilter session qtssRTSPSesID: %s\n", qtssRTSPSesIDString);
    
    char* qtssRTSPReqFullRequestString = NULL;
    (void)QTSS_GetValueAsString(theRTSPRequest, qtssRTSPReqFullRequest, 0,  &qtssRTSPReqFullRequestString);
    qtss_printf("QTSSIcecastAuthModule::RTSPFilter: request qtssRTSPReqFullRequest: %s\n", qtssRTSPReqFullRequestString);
    
    /* will want to modify this for proper tokenization, but it works for now */ 
    char username[255];
    bool usernameset = false;
    char password[255];
    bool passwordset = false;
    
    Bool16 requiredAuthParametersProvided = false;
    
    if(index(qtssRTSPReqFullRequestString, '?')){ 
        char buf[512]; 
        snprintf(buf, 512, qtssRTSPReqFullRequestString);
        
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
        //printf("queryString: %s\n", queryString);
        // we should now have our url
        
        char* tmp = strtok(queryString, "=&");
        
        int iters;
    
        for (iters=0; (tmp != NULL); iters++)
        {    
            char name[255]; // I'm asking for a buffer overflow, aren't I? TODO - check this.
            if ((iters % 2) != 1) {
                // even - its a name. this will always be 'first'
                strcpy(name, tmp);
                //printf("name: %s\n", tmp);
            }
            else {
                // non-even, its a value. this will always come second
                //printf("value: %s\n", tmp);
                
                if (strcmp(name, "u") == 0) {
                    // this value is the username
                    //printf("name is currently: %s. username being set to %s\n", name, tmp);
                    strcpy(username, tmp);
                    usernameset = true;
                }
                else if (strcmp(name, "p") == 0) {
                    // this value is the username
                    //printf("name is currently: %s. password being set to %s\n", name, tmp);
                    strcpy(password, tmp);
                    passwordset = true;
                }
                
            }
            tmp = strtok(NULL, "=&");
        }
        
        //printf("username: %s, password: %s\n\n", username, password);
        
        if (usernameset && passwordset) {
            printf("QTSSIcecastAuthModule::RTSPFilter username and password have been provided.\n");
            requiredAuthParametersProvided = true;
        }
        
    }
    
    if (requiredAuthParametersProvided) {
        // we have a username and password. set them on the RTSP session, so they can be validated later.
        
        QTSS_Error setErr = QTSS_SetValue(theRTSPSession, attrRtspSessionProvidedUsername, 0,  &username, sizeof(username));
        QTSS_SetValue(theRTSPSession, attrRtspSessionProvidedPassword, 0,  &password, sizeof(password));
        
        PrintQTSSError("QTSSIcecastAuthModule::RTSPFilter", "after username set", setErr);
        
        char* providedUsername = NULL;
        (void)QTSS_GetValueAsString(theRTSPSession, attrRtspSessionProvidedUsername, 0,  &providedUsername);
        printf("QTSSIcecastAuthModule::RTSPFilter: Provided username extracted from session right after set: %s\n", providedUsername);

        char* providedPassword = NULL;
        (void) QTSS_GetValueAsString(theRTSPSession, attrRtspSessionProvidedPassword, 0, &providedPassword);
        printf("QTSSIcecastAuthModule::RTSPFilter: Provided password extracted from session right after set: %s\n", providedPassword);          
    }
    else {
        // WRONG. username and password weren't provided, do nothing - we will handle later.
    }
    
    // TODO - we should be cleaning up more things here, I think.
    QTSS_Delete(qtssRTSPReqFullRequestString);
    
    return QTSS_NoErr;
}


/*
 * This method is used to capture the full session ID details, and to reject the session. 
 * The username and password from the query string can't be grabbed here, we need to
 * do that in the Filter. This is called AFTER Filter
 */
QTSS_Error RTSPPreProcess(QTSS_StandardRTSP_Params* inParams) {
    QTSS_Error              theErr = QTSS_NoErr;
    QTSS_RTSPRequestObject  theRTSPRequest = inParams->inRTSPRequest;
    QTSS_RTSPSessionObject  theRTSPSession = inParams->inRTSPSession;
    QTSS_RTSPHeaderObject   theRTSPHeader = inParams->inRTSPHeaders;
    QTSS_ClientSessionObject theClientSession = inParams->inClientSession;

    Bool16 sessionValid = false;
    
    // see if the method is bypassable. if it is, skip processing
    qtss_printf("QTSSIcecastAuthModule::RTSPPreProcess: about to check if the method is bypassable\n");
    if (IsRequestMethodBypassable(&theRTSPRequest)) return QTSS_NoErr;
            
    //  see if the client is in the bypass list. if they are, skip all processing
    if (IsClientInBypassList(&theRTSPSession)) return QTSS_NoErr; 
    
    // check to see if the session is already auth'd. If it is, skip processing
    if (IsRTSPSessionAuthenticated(&theRTSPSession)) {
        printf("QTSSIcecastAuthModule::RTSPPreProcess RTSP session is authenticated, do nothing.\n");
        return QTSS_NoErr; // we are authenticated, don't do anything
    }
        
    
    char* providedUsername = NULL;
    (void)QTSS_GetValueAsString(theRTSPSession, attrRtspSessionProvidedUsername, 0,  &providedUsername);
    printf("QTSSIcecastAuthModule::RTSPPreProcess: Provided username extracted from session: %s\n", providedUsername);
    
    char* providedPassword = NULL;
    (void)QTSS_GetValueAsString(theRTSPSession, attrRtspSessionProvidedPassword, 0,  &providedPassword);
    printf("QTSSIcecastAuthModule::RTSPPreProcess: Provided password extracted from session: %s\n", providedPassword);
    
    // check to see if the username and password have been provided. If they are, process. if not
    // do nothing, we will default to an invalid session
    if (providedUsername != NULL && providedPassword != NULL) {
        
        printf("QTSSIcecastAuthModule::RTSPPreProcess: about to call authorize session\n");
        // if we get to this point we have credentials that need to be validated, so validate them.
        sessionValid = CallAuthorizeSession(&theClientSession, &theRTSPSession, &theRTSPRequest, providedUsername, providedPassword);
        
        
        
        


        // request, qtssRTSPReqFilePath - the mount point (?)
        // request, qtssRTSPReqURI - the request URI (query params parsed from here?)
        // request, qtssRTSPReqAbsoluteURL - the request url with RTSP.
        // request, qtssRTSPReqFullRequest - the full request
        // session, qtssRTSPSesID - the session id

        // note - QTSS_GetValueAsString is the least efficent method - should move to one of the more efficent methods. 
//
//    char* qtssRTSPReqFilePathString = NULL;
//    (void)QTSS_GetValueAsString(theRTSPRequest, qtssRTSPReqFilePath, 0,  &qtssRTSPReqFilePathString);
//    printf("QTSSIcecastAuthModule::RTSPPreProcess: request qtssRTSPReqFilePath: %s\n", qtssRTSPReqFilePathString);
//
//        char* qtssRTSPReqURIString = NULL;
//        (void)QTSS_GetValueAsString(theRTSPRequest, qtssRTSPReqURI, 0,  &qtssRTSPReqURIString);
//        printf("QTSSIcecastAuthModule::RTSPPreProcess: request qtssRTSPReqURI: %s\n", qtssRTSPReqURIString);
//
//    char* qtssRTSPReqAbsoluteURLString = NULL;
//    (void)QTSS_GetValueAsString(theRTSPRequest, qtssRTSPReqAbsoluteURL, 0,  &qtssRTSPReqAbsoluteURLString);
//    printf("QTSSIcecastAuthModule::RTSPPreProcess: request qtssRTSPReqAbsoluteURL: %s\n", qtssRTSPReqAbsoluteURLString);

        





//        //QTSS_Delete(qtssRTSPReqFilePathString);
//        QTSS_Delete(qtssRTSPReqURIString);
//        //QTSS_Delete(qtssRTSPReqAbsoluteURLString);
//        QTSS_Delete(qtssRTSPSesIDString);
    }
    else {
        
        printf("QTSSIcecastAuthModule::RTSPPreProcess: username and/or password are NULL\n");
    }
    
    // set the auth status on the RTSP session
    (void)QTSS_SetValue(theRTSPSession, attrRtspSessionAuthenticated, 0,  &sessionValid, sizeof(sessionValid));
    
    if (sessionValid) {
        // valid session, return
        
        return QTSS_NoErr;
    }
    else {
        // not a valid session, error
        char* accessDeniedMessage = "Access DENIED";
        StrPtrLen accessDeniedMessageStr(accessDeniedMessage,sizeof(accessDeniedMessage));
        (void)QTSSModuleUtils::SendErrorResponseWithMessage(theRTSPRequest, qtssClientForbidden, &accessDeniedMessageStr);
        
        return QTSS_NoErr;
    }
}

/**
 * This is called when a clients session ends - use this to update services
 */
static QTSS_Error ClientSessionClosing(QTSS_ClientSessionClosing_Params* inParams) {
    QTSS_ClientSessionObject theClientSession = inParams->inClientSession;
    
    printf("QTSSIcecastAuthModule::ClientSessionClosing called"); 
    
//    QTSS_TimeVal clientSessCreateTime = NULL;
//    UInt32 createTimeLen = sizeof(clientSessCreateTime);
//    QTSS_GetValue(theClientSession, qtssCliSesCreateTimeInMsec, 0, (void*)&clientSessCreateTime, &createTimeLen); 
//    printf("QTSSIcecastAuthModule::ClientSessionClosing: Client session start time (millis): %ld\n", (long)clientSessCreateTime);

    char* iceSessID = NULL;
    QTSS_Error getSessErr = QTSS_GetValueAsString(theClientSession, attrClientSessionFullSessionID, 0, &iceSessID);
    if (getSessErr == QTSS_ValueNotFound) {
        // this client session doesn't have a session ID, therefore probably came in via
        // the IP exclusion list. Ignore
        printf("QTSSIcecastAuthModule::ClientSessionClosing: session ID not found. probably in exclusion list.\n");
    }
    else {
        // handle the session closing.
        printf("QTSSIcecastAuthModule::ClientSessionClosing: the full session ID: %s\n", iceSessID);
        CallEndSession(&theClientSession);
    }
    

    return QTSS_NoErr;
}

static Bool16 CallAuthorizeSession(QTSS_ClientSessionObject* theClientSession, QTSS_RTSPSessionObject* theRTSPSession,
        QTSS_RTSPRequestObject* theRTSPRequest, char* username, char* password) {
    qtss_printf("QTSSIcecastAuthModule::CallAuthorizeSession called\n");
    //{ :action => "listener_add", :server => "server", :port => "8000", :client => "sessionidone",
    //  :mount => "somemount.sdp", :user => "lstoll", :pass => @working_hash, :ip => "127.0.0.1", :agent => "RSPEC"}

    // generate the client session id (and save in client) format <start time millis>-<rtsp session id>
    char ice_sessid[128];

    QTSS_TimeVal clientSessCreateTime = NULL;
    UInt32 createTimeLen = sizeof (clientSessCreateTime);
    QTSS_GetValue(*theClientSession, qtssCliSesCreateTimeInMsec, 0, (void*) & clientSessCreateTime, &createTimeLen);

    char* qtssRTSPSesIDString = NULL;
    (void) QTSS_GetValueAsString(*theRTSPSession, qtssRTSPSesID, 0, &qtssRTSPSesIDString);

    sprintf(ice_sessid, "%lld-%s", clientSessCreateTime, qtssRTSPSesIDString);

    printf("QTSSIcecastAuthModule::CallAuthorizeSession generated session id: %s\n", ice_sessid);

    (void) QTSS_SetValue(*theClientSession, attrClientSessionFullSessionID, 0, &ice_sessid, sizeof (ice_sessid));

    // get the user agent
    char* userAgentString = NULL;
    (void) QTSS_GetValueAsString(*theClientSession, qtssCliSesFirstUserAgent, 0, &userAgentString);
    printf("QTSSIcecastAuthModule::CallAuthorizeSession: request user agent: %s\n", userAgentString);
    
    // get the client IP address
    char remoteAddress[20] = {0};
    StrPtrLen theClientIPAddressStr(remoteAddress,sizeof(remoteAddress));
    (void)QTSS_GetValue(*theRTSPSession, qtssRTSPSesRemoteAddrStr, 0, (void*)theClientIPAddressStr.Ptr, &theClientIPAddressStr.Len);
    
    // get the mount point
    char mountPoint[128] = {0};
    StrPtrLen mountPointStr(mountPoint,sizeof(mountPoint));
    (void)QTSS_GetValue(*theRTSPRequest, qtssRTSPReqURI, 0, (void*)mountPointStr.Ptr, &mountPointStr.Len);
    printf("QTSSIcecastAuthModule::CallAuthorizeSession: mount point: %s\n", mountPoint);
    // and set it in the client for use on session end
    (void) QTSS_SetValue(*theClientSession, attrClientSessionMountPoint, 0, mountPointStr.Ptr, mountPointStr.Len);
    
    char postdata[512];
    
    qtss_sprintf(postdata, "action=listener_add&server=%s&port=554&client=%s&mount=%s&user=%s&pass=%s&ip=%s&agent%s",
            hostname, ice_sessid, mountPoint, username, password, remoteAddress, userAgentString);
    
    
    printf("QTSSIcecastAuthModule::CallAuthorizeSession: generated postdata: %s\n", postdata);
    
    printf("QTSSIcecastAuthModule::CallAuthorizeSession: i would post this to: %s\n", sStartSessionEndpoint);
    
    return true;
    
//    
//    CURL *easyhandle = NULL; 
//    easyhandle = curl_easy_init();
//    CURLcode curl_code;
//
//    
//    curl_easy_setopt(easyhandle, CURLOPT_POSTFIELDS, postdata);
//    curl_easy_setopt(easyhandle, CURLOPT_URL, "http://posthere.com/");
//    curl_easy_perform(easyhandle); /* post away! */
//
//    long http_code = 0;
//    curl_easy_getinfo(easyhandle, CURLINFO_HTTP_CODE, &http_code);
//    if (http_code == 200 && curl_code != CURLE_ABORTED_BY_CALLBACK) {
//        // the call to the remote server was OK. pass.
//        return true;
//    } else {
//        return false;
//    }
//    return false;
}

static void CallEndSession(QTSS_ClientSessionObject* theClientSession) {
    // action=listener_remove&server=myserver.com&port=8000&client=1&mount=/live&user=&pass=&duration=3600
    
    // the duration
    SInt64* connectedTime = NULL;
    UInt32 connectedTimeLen = sizeof(connectedTime);
    (void)QTSS_GetValuePtr(*theClientSession, qtssCliSesTimeConnectedInMsec, 0, (void**)&connectedTime, &connectedTimeLen);
    qtss_printf("QTSSIcecastAuthModule::CallEndSession connected time in seconds %li\n", (*connectedTime / 1000));
    long duration = (long)*connectedTime / 1000;
    
    // the mount point
    char mountPoint[128] = {0};
    StrPtrLen mountPointStr(mountPoint,sizeof(mountPoint));
    (void)QTSS_GetValue(*theClientSession, attrClientSessionMountPoint, 0, (void*)mountPointStr.Ptr, &mountPointStr.Len);
    printf("QTSSIcecastAuthModule::CallEndSession: mount point: %s\n", mountPoint);
    
    
    // TODO - we don't use this data on the remote end (yet), but implement - will probably need to copy 
    // credentials into the client session from the RTSP session (annoying, but both aren't visible at all times)
//    // username and password
//    char* username = NULL;
//    (void)QTSS_GetValueAsString(theRTSPSession, attrRtspSessionProvidedUsername, 0,  &username);
//    printf("QTSSIcecastAuthModule::CallEndSession: Provided username extracted from client session: %s\n", username);
//    
//    char* password = NULL;
//    (void)QTSS_GetValueAsString(theRTSPSession, attrRtspSessionProvidedPassword, 0,  &password);
//    printf("QTSSIcecastAuthModule::CallEndSession: Provided password extracted from client session: %s\n", password);
    
    // ice session id
    char* iceSessID = NULL;
    QTSS_Error getSessErr = QTSS_GetValueAsString(*theClientSession, attrClientSessionFullSessionID, 0, &iceSessID);
    
    char postdata[512];
    
    qtss_sprintf(postdata, "action=listener_remove&server=%s&port=554&client=%s&mount=%s&user=%s&pass=%s&duration=%li",
            hostname, iceSessID, mountPoint, "", "", duration);
    
    
    printf("QTSSIcecastAuthModule::CallAuthorizeSession: generated postdata: %s\n", postdata);
    
    printf("QTSSIcecastAuthModule::CallAuthorizeSession: i would post this to: %s\n", sEndSessionEndpoint);
    
}

/**
 * For the given RTSP session, will return true if the client is already flagged
 * as authenticated, false if they arent. if the value is not initialized, this
 * method will intitialize it. This is used to ensure a session is only authenticated
 * once.
 */
static Bool16 IsRTSPSessionAuthenticated(QTSS_RTSPSessionObject* theRTSPSession) {
    printf("QTSSIcecastAuthModule::IsRTSPSessionAuthenticated method start\n");
    Bool16* alreadyAuthenticated = false;
    UInt32 theLen = 0;
    QTSS_Error getAlreadyAuthError = QTSS_GetValuePtr(*theRTSPSession, attrRtspSessionAuthenticated, 0, (void**)&alreadyAuthenticated, &theLen);
    //printf("QTSSIcecastAuthModule::IsRTSPSessionAuthenticated read value of already aythenticated: &i\n", alreadyAuthenticated);
    if (getAlreadyAuthError == QTSS_ValueNotFound) {
        // the value hasn't been set yet. initialize it to false, and return false.
        // TODO - check how to set a default variable (if possible), so we don't have to rely on this.
        
        Bool16 authenticated = false;
      
        (void)QTSS_SetValue(*theRTSPSession, attrRtspSessionAuthenticated, 0,  &authenticated, sizeof(authenticated));
        
        // we had to initialize, so def. not logged in
        return false;
    }
    else if (*alreadyAuthenticated) {
        // we are already logged in
        printf("QTSSIcecastAuthModule::IsRTSPSessionAuthenticated session already authenticated\n");
        return true;
    }
    else if (!*alreadyAuthenticated && getAlreadyAuthError == QTSS_NoErr) {
        // we are not authed and there was no error, to return
        return false;
    }
    else {
        //printf("QTSSIcecastAuthModule::RTSPFilter ERROR while looking up not logged in\n");
        PrintQTSSError("QTSSIcecastAuthModule::IsRTSPSessionAuthenticated", "while looking up not logged in", getAlreadyAuthError);
        return false;
    }
}

/** 
 * For the given rtsp session, will return true if the client is in the configured
 * bypass list in the prefs, false if they aren't
 */
static Bool16 IsClientInBypassList(QTSS_RTSPSessionObject* theRTSPSession) {
    qtss_printf("QTSSIcecastAuthModule::IsClientInBypassList method start\n");
    // don't forget to *deref the param!
    char remoteAddress[20] = {0};
    StrPtrLen theClientIPAddressStr(remoteAddress,sizeof(remoteAddress));
    QTSS_Error err = QTSS_GetValue(*theRTSPSession, qtssRTSPSesRemoteAddrStr, 0, (void*)theClientIPAddressStr.Ptr, &theClientIPAddressStr.Len);
    if (err != QTSS_NoErr) return false;

    if  (QTSSModuleUtils::AddressInList(sModulePrefs, sIPBypassListID, &theClientIPAddressStr)) {
        qtss_printf("QTSSIcecastAuthModule::IsClientInBypassList client is in list\n");
        return true;
    }
    else {
        qtss_printf("QTSSIcecastAuthModule::IsClientInBypassList client is NOT in list\n");
        return false;
    }
}

/**
 * For the given RTSP request, check to see if we can bypass authentication -
 * currently filters for OPTIONS / request (these return no music to the listener,
 * so don't need to be authenticated - and at least the S60 RealPlayer sends this
 * request for / - so we need to let it through, and authenticate when it actually
 * requests a stream
 */
static Bool16 IsRequestMethodBypassable(QTSS_RTSPRequestObject* theRTSPRequest) {
    QTSS_RTSPMethod* theMethod = NULL;
    UInt32 theLen = 0;
 
    QTSS_Error theErr = QTSS_GetValuePtr(*theRTSPRequest, qtssRTSPReqMethod, 0,
        (void**)&theMethod, &theLen);
    
    if ((theErr != QTSS_NoErr) || (theLen != sizeof(QTSS_RTSPMethod))) {
        return false;  // an error occured, dont allow bypass
    }
    else {
        qtss_printf("QTSSIcecastAuthModule::IsRequestMethodBypassable the method is %i\n", *theMethod);
        if (*theMethod == qtssOptionsMethod) {
            // we can bypass this one
            return true;
        }
        else {
            // cant bypass
            return false;
        }
    }
}


/**
 * This method can be used to print out the error type from a QTSS_Error
 */
void PrintQTSSError(const char msgPrefix[], const char msgSuffix[], QTSS_Error theErr) {
    // change this to a case that sets message, then does the sigle printf.
    //printf("error code about to be rendered is %i\n", theErr);
    if (theErr == QTSS_NoErr) {
        printf("%s no error after %s\n", msgPrefix, msgSuffix);
    } else if (theErr == QTSS_BadIndex) {
        printf("%s bad index error %s\n", msgPrefix, msgSuffix);
    } else if (theErr == QTSS_BadArgument) {
        printf("%s bad argument error %s\n", msgPrefix, msgSuffix);
    } else if (theErr == QTSS_ReadOnly) {
        printf("%s read only error %s\n", msgPrefix, msgSuffix);
    } else if (theErr == QTSS_AttrDoesntExist) {
        printf("%s attribute doesnt exist error %s\n", msgPrefix, msgSuffix);
    } else if (theErr == QTSS_ValueNotFound) {
        printf("%s value not found error %s\n", msgPrefix, msgSuffix);
    } else {
        printf("%s UNKNOWN ERROR - ADD MORE ERRORS TO LIST (error code %i) %s\n", msgPrefix, theErr, msgSuffix);
    }
}
