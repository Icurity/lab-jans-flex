# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2018, Janssen
#
# Author: Yuriy Zabrovarnyy
#
#
from io.jans.as.model.common import *
from io.jans.model.custom.script.type.introspection import IntrospectionType
from io.jans.as.server.service import SessionIdService, ScopeService, AttributeService
from io.jans.service.cdi.util import CdiUtil
from java.lang import String

from io.jans.util import StringHelper

try:
    import json
except ImportError:
    import simplejson as json

def log(type, message, code=None):
    """Prints the specified args in a predictable JSON format. This eases scraping the script logs.

    Args:
        type: The type of log entry this represents. Possible types include "info" and "error".
        code: (Optional) A code that you would like to associate with your message. This can ease
          scraping the logs.
        message: (Optional) The message associated with your log entry
    """

    logEntry = {
        "script": "introspetion.py",
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

class Introspection(IntrospectionType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        logInfo("Initialization")

        return True

    def destroy(self, configurationAttributes):
        logInfo("Destroy")
        logInfo("Destroyed successfully")
        return True

    def getApiVersion(self):
        return 11

    # Returns boolean, true - apply introspection method, false - ignore it.
    # This method is called after introspection response is ready. This method can modify introspection response.
    # Note :
    # responseAsJsonObject - is org.codehaus.jettison.json.JSONObject, you can use any method to manipulate json
    # context is reference of org.gluu.oxauth.service.external.context.ExternalIntrospectionContext (in https://github.com/GluuFederation/oxauth project, )
    def modifyResponse(self, responseAsJsonObject, context):
        token = context.getHttpRequest().getParameter("token")
        if token is None:
            logError("There is no token in request")
            return False

        authorizationGrantList = CdiUtil.bean(AuthorizationGrantList)
        authorizationGrant = authorizationGrantList.getAuthorizationGrantByAccessToken(token);
        if authorizationGrant is None:
            logError("Failed to load authorization grant by token")
            return False

        # Put user_id into response
        responseAsJsonObject.accumulate("user_id", authorizationGrant.getUser().getUserId())

        # Put authorized claims into response
        claims = [];
        scopeService = CdiUtil.bean(ScopeService)
        attributeService = CdiUtil.bean(AttributeService)
        for x in authorizationGrant.getScopes():
            if (StringHelper.equalsIgnoreCase(x, "openid")):
                continue
            scope = scopeService.getScopeById(x)
            if (scope.getOxAuthClaims() != None):
                # Add claims
                for y in scope.getOxAuthClaims():
                    gluuAttribute = attributeService.getAttributeByDn(y);
                    claims.append(gluuAttribute.getOxAuthClaimName())
        #convert list to set to get rid of duplicates then back to list
        responseAsJsonObject.accumulate("bvn_data", list(set(claims)))

        # Put custom parameters into response
        sessionDn = authorizationGrant.getSessionDn();
        if sessionDn is None:
            # There is no session
            return True

        sessionIdService = CdiUtil.bean(SessionIdService)
        session = sessionIdService.getSessionByDn(sessionDn)
        if sessionDn is None:
            logError("Failed to load session '%s'" % sessionDn)
            return False

        # Return session_id
        responseAsJsonObject.accumulate("session_id", sessionDn)
        
        sessionAttributes = session.getSessionAttributes()
        if sessionAttributes is None:
            # There is no session attributes
            return True

        # Append custom claims
        if session.getSessionAttributes().containsKey("_tx_id"):
            responseAsJsonObject.accumulate("_tx_id", sessionAttributes.get("_tx_id"))
        if sessionAttributes.containsKey("_client_name"):
            responseAsJsonObject.accumulate("client_name", sessionAttributes.get("_client_name"))
        if sessionAttributes.containsKey("client_ref"):
            responseAsJsonObject.accumulate("client_ref", sessionAttributes.get("client_ref"))

        return True

