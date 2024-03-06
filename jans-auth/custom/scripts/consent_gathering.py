# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2017, Gluu
#
# Author: Yuriy Movchan
#

from io.jans.model.custom.script.type.authz import ConsentGatheringType
from jakarta.faces.application import FacesMessage
from io.jans.jsf2.message import FacesMessages
from java.util import  HashSet, ArrayList, Arrays
from io.jans.as.server.security import Identity
from io.jans.service.cdi.util import CdiUtil
from io.jans.util import StringHelper
from io.jans.as.server.service import SessionIdService, ScopeService, AttributeService

import java
import random
import datetime
import sys
import traceback
import json
    
class LogCodes:
    """All the codes that we use for logging. This eases log scraping."""
    SYSTEM_FAILURE = "CODE-FAILED"
    CONSENT_APPROVED = "CONSENT-APPROVED"
    CONSENT_DENIED = "CONSENT-DENIED"

def log(type, message, code=None):
    """Prints the specified args in a predictable JSON format. This eases scraping the script logs.

    Args:
        type: The type of log entry this represents. Possible types include "info" and "error".
        code: (Optional) A code that you would like to associate with your message. This can ease
          scraping the logs.
        message: (Optional) The message associated with your log entry
    """

    logEntry = {
        "script": "consent_gathering.py",
        "type": type,
        "message": message
    }

    if code is not None:
        logEntry["code"] = code

    print(json.dumps(logEntry))

def logInfo(message, code=None):
    """Convenience function to log an info message.

    Args:
        message: The informational message to log.
    """
    #if self.log_level == 'DEBUG'
    log("info", message, code)

def logError(message, code=None):
    """Convenience function to log an error message.

    Args:
        code: A code that you would like to associate with your error.
        message: (Optional) The error message to log.
    """

    log("error", message, code)

class ConsentGathering(ConsentGatheringType):

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        logInfo("Initializing")
        logInfo("Initialized successfully")

        return True

    def destroy(self, configurationAttributes):
        logInfo("Destroy")
        logInfo("Destroyed successfully")

        return True

    def getApiVersion(self):
        return 11

    # Main consent-gather method. Must return True (if gathering performed successfully) or False (if fail).
    # All user entered values can be access via Map<String, String> context.getPageAttributes()
    def authorize(self, step, context): # context is reference of org.gluu.oxauth.service.external.context.ConsentGatheringContext
        logInfo("Consent initiated...")
        _city = None
        _country = None
        _user_id = None
        _client_id = None
        _client_name = None
        _remote_ip = None
        _tx_id = None
        _client_ref = None
        _reqScopes = None

        if step == 1:
            session = CdiUtil.bean(SessionIdService).getSessionId()
            if session.getSessionAttributes().containsKey("client_id"):
                _client_id = session.getSessionAttributes().get("client_id")
            if session.getSessionAttributes().containsKey("client_name"):
                _client_name = session.getSessionAttributes().get("client_name")
            if session.getSessionAttributes().containsKey("_tx_id"):
                _tx_id = session.getSessionAttributes().get("_tx_id")
            if session.getSessionAttributes().containsKey("_city"):
                _city = session.getSessionAttributes().get("_city")    
            if session.getSessionAttributes().containsKey("_country"):
                _country = session.getSessionAttributes().get("_country")
            if session.getSessionAttributes().containsKey("_remote_ip"):
                _remote_ip = session.getSessionAttributes().get("_remote_ip")
                if StringHelper.isNotEmpty(_remote_ip):
                    if ("," in _remote_ip):
                        _remote_ip = _remote_ip.split(",")[0]
            if session.getSessionAttributes().containsKey("auth_user"):
                _user_id = session.getSessionAttributes().get("auth_user")     
            if session.getSessionAttributes().containsKey("scope"):
                _reqScopes = session.getSessionAttributes().get("scope")
                #print "Scopes granted: %s " % _reqScopes
            if session.getSessionAttributes().containsKey("client_ref"):
                _client_ref = session.getSessionAttributes().get("client_ref")  
            allowButton = context.getRequestParameters().get("authorizeForm:allowButton")
            if (allowButton != None) and (len(allowButton) > 0):
                print "{\"logtype\":\"consent_granted\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"client_id\": \"%s\",\"scopes\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (_tx_id, _client_ref, _client_id, _reqScopes, _client_name, _remote_ip, _city, _country, _user_id, datetime.datetime.now())
                return True
                
            print "{\"logtype\":\"consent_declined\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"client_id\": \"%s\",\"scopes\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (_tx_id, _client_ref, _client_id, _reqScopes, _client_name, _remote_ip, _city, _country, _user_id, datetime.datetime.now())
        elif step == 2:
            allowButton = context.getRequestParameters().get("authorizeForm:allowButton")
            print "Consent script. Allow button: %s" % allowButton
            if (allowButton != None) and (len(allowButton) > 0):
                logInfo("Authorization allowed or step 2")
                return True

            logInfo("Authorization declined or step 2")

        return False

    def getNextStep(self, step, context):
        return -1

    def prepareForStep(self, step, context):
         
        print "Consent script initiated"
        
        if not context.isAuthenticated():
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            logInfo("User is not authenticated. Aborting authorization flow ...")
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "You have access this page directly. This is not allowed.")
            return False
        
        GrantedScopes = None
        if step == 1:
            session = CdiUtil.bean(SessionIdService).getSessionId()
            sessionAtt = CdiUtil.bean(SessionIdService)

            scopeService = CdiUtil.bean(ScopeService)
            scopeList = scopeService.getAllScopesList()
            attributeService = CdiUtil.bean(AttributeService)  
            GrantedScopes = sessionAtt.getSessionAttributes(session).get("scope")
            print "Consent script. Granted scopes: %s" % GrantedScopes

            try:
                for eachScope in GrantedScopes.split(" "):
                    print "Consent script. EachScope: %s" % eachScope             
                    for scope in scopeList:
                        claimList =  ArrayList()
                        if (scope.getDisplayName() == eachScope):
                            for claim in scope.getClaims():
                                print "Consent script. Get scope claims: %s" %  scope.getClaims()
                                claimName = attributeService.getAttributeByDn(claim).getDescription()
                                claimList.add(claimName)
                            context.addSessionAttribute(str(eachScope),str(claimList).replace("[","").replace("]",""))
                            print "Consent script. Each scope requested: %s" % claimName
            except:
                logError(
                    "prepareForStep. event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to process claims due to exception '%s' with message: '%s' and trace: '%s'." % (
                        "identity.getSessionId().getId()", 
                        "identity.getSessionId().getSessionAttributes().get()", 
                        "identity.getSessionId().getSessionAttributes().get()",
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.SYSTEM_FAILURE
                )
            return True
        if step == 2:
            pageAttributes = context.getPageAttributes()
            
            # Generate random consent gathering request
            consentRequest = "Requested transaction #%s approval for the amount of sum $ %s.00" % ( random.randint(100000, 1000000), random.randint(1, 100) )
            pageAttributes.put("consent_request", consentRequest)
            return True

        return True

    def getStepsCount(self, context):
        return 1

    def getPageForStep(self, step, context):
        if step == 1:
            return "/authz/authorize.xhtml"
        elif step == 2:
            return "/authz/transaction.xhtml"

        return ""