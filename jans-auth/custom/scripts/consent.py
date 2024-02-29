# Janssen Project software is available under the Apache 2.0 License (2004). See http://www.apache.org/licenses/ for full text.
# Copyright (c) 2020, Janssen Project
#
# Author: Yuriy Movchan
#

# Requires the following custom properties and values:
#   otp_type: totp/hotp
#   issuer: Janssen Inc
#   otp_conf_file: /etc/certs/otp_configuration.json
#
# These are non mandatory custom properties and values:
#   label: Janssen OTP
#   qr_options: { width: 400, height: 400 }
#   registration_uri: https://ce-dev.jans.org/identity/register

try:
    import json
except ImportError:
    import simplejson as json
import jarray
import sys
import random
from datetime import datetime, timedelta;
import time
import traceback


#import json
#import sys
#Unused imports
from com.google.common.io import BaseEncoding
from com.lochbridge.oath.otp import HOTP
from com.lochbridge.oath.otp import HOTPValidator
from com.lochbridge.oath.otp import HmacShaAlgorithm
from com.lochbridge.oath.otp import TOTP
from com.lochbridge.oath.otp.keyprovisioning import OTPAuthURIBuilder
from com.lochbridge.oath.otp.keyprovisioning import OTPKey
from com.lochbridge.oath.otp.keyprovisioning.OTPKey import OTPType



from java.security import SecureRandom
from java.util import HashSet, ArrayList, Arrays
from java.util.concurrent import TimeUnit
from jakarta.faces.application import FacesMessage
from io.jans.jsf2.message import FacesMessages
from io.jans.model.custom.script.type.auth import PersonAuthenticationType
from io.jans.as.server.service import AuthenticationService, SessionIdService, ClientService
from io.jans.as.server.service import UserService
#from io.jans.as.server.service import ClientAuthorizationsService
from io.jans.as.server.security import Identity
from io.jans.as.server.util import ServerUtil
from io.jans.service.cdi.util import CdiUtil

from org.apache.http.params import CoreConnectionPNames
from io.jans.as.server.service.net import HttpService
from io.jans.as.common.model.common import User
from io.jans.as.server.model.authorize import ScopeChecker
#from io.jans.as.server.model.ldap import ClientAuthorization
from io.jans.service import MailService
from java.nio.charset import Charset

from io.jans.util import StringHelper, ArrayHelper

class LogCodes:
    """All the codes that we use for logging. This eases log scraping."""
    LOGIN_SUCCESSFUL = "LOGIN-SUCCESSFUL"
    LOGIN_FAILED = "LOGIN-FAILED"
    PROFILE_LOOKUP_SUCCESS = "PROFILE-LOOKUP-SUCCESS"
    API_CALL_SUCCESS = "API-CALL-SUCCESS"
    CREATE_GLUU_SUCCESS = "CREATE-GLUU-SUCCESS"
    PROFILE_NOT_FOUND = "PROFILE-NOT-FOUND"
    PROFILE_LOOKUP_FAIL = "PROFILE-LOOKUP-FAIL"
    API_CALL_FAIL = "API-CALL-FAIL"
    CREATE_GLUU_USER_FAIL = "CREATE-GLUU-USER-FAIL"
    CONTACT_INFO_FAIL = "CONTACT-INFO-FAIL"
    OTP_DELIVERY_FAIL = "OTP-DELIVERY-FAIL"
    OTP_VALIDATION_FAIL = "OTP-VALIDATION-FAIL"
    OTP_NUM_ICAD_MATCH_FAIL = "OTP-NUM-ICAD-MATCH-FAIL"
    OTP_NUM_ICAD_MATCH_SUCCESS = "OTP-NUM-ICAD-MATCH-SUCCESS"

def log(type, message, code=None):
    """Prints the specified args in a predictable JSON format. This eases scraping the script logs.

    Args:
        type: The type of log entry this represents. Possible types include "info" and "error".
        code: (Optional) A code that you would like to associate with your message. This can ease
          scraping the logs.
        message: (Optional) The message associated with your log entry
    """

    logEntry = {
        "script": "consent_otp.py",
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

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        print "Consent. Initialization"

        try:
            self.api_host = configurationAttributes.get("api_base_domain").getValue2()
        except:
            print "Consent. Initialization. Property otp_type is mandatory"
            return False

        try:
            self.x_consumer_custom_id = configurationAttributes.get("x-consumer-custom-id").getValue2()
        except:
            print "Consent. Initialization. Property value otp_type is invalid"
            return False

        try:
            self.x_consumer_unique_id = configurationAttributes.get("x-consumer-unique-id").getValue2()
        except:
            print "Consent. Initialization. Property issuer is mandatory"
            return False

        try:
            self.otp_type = configurationAttributes.get("otp_type").getValue2()
        except:
            print "Consent. Initialization. Property issuer is mandatory"
            return False
        
        try:
            self.otp_ttl = configurationAttributes.get("otp_ttl").getValue2()
        except:
            print "Consent. Initialization. Property issuer is mandatory"
            return False
        
        try:
            self.log_level = configurationAttributes.get("log_level").getValue2()
        except:
            print "Consent. Initialization. Property issuer is mandatory"
            return False
        
        print "Consent. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "OTP. Destroy"
        print "OTP. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 11
        
    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "getNextStep Invoked"
        # If user not pass current step change step to previous
        identity = CdiUtil.bean(Identity)
        retry_current_step = identity.getWorkingParameter("retry_current_step")
        if retry_current_step:
            print "OTP. Get next step. Retrying current step %s" % step
            # Remove old QR code
            #identity.setWorkingParameter("super_gluu_request", "timeout")
            resultStep = step
            return resultStep
        return -1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        """
        This step tries to find the user in GLUU using the entered BVN number.
        If the user was found then it extracts their contact details. If the user was not found then it
        determines which consent screen to show to the user.

        Returns:
            True if the step succeeded, or False otherwise.
        """
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        #facesMessages = CdiUtil.bean(FacesMessages)
        #facesMessages.setKeepMessages()

        print "Consent script. Preparing to step 1 >> Authenticate method"

        if step == 1:
            # If the user profile was not found in Gluu then always call BVN API
            print "Consent Script. Searched user on Flex creds: %s" % credentials
            authenticated_user = self.searchForBvnUser(credentials)
            user_id = credentials.getUsername()
            print "Consent script. User name is: %s " % user_id 
            if authenticated_user == None:
                logInfo(
                    "authenticate:Step 1: Failed to find or authn user in Gluu. Calling BVN api now. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_id
                        )
                )
                # lets check for the user from BVN DB
                bvn_user = None
                try:
                   bvn_user = self.fetchUserFromBVNApi(user_id, identity)
                except:
                    logError(
                            "authenticate:Step 1: event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to call BVN api due to exception '%s' with message: '%s' and trace: '%s'." % (
                                identity.getSessionId().getId(), 
                                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                                user_id,
                                sys.exc_info()[0],
                                sys.exc_info()[1],
                                traceback.format_tb(sys.exc_info()[2])[-1]
                            ),
                            LogCodes.LOGIN_FAILED
                        )
                if bvn_user == None:
                    #facesMessages.add(FacesMessage.SEVERITY_ERROR, "Your BVN details couldn't be found. Try again.")
                    self.setMessageError(FacesMessage.SEVERITY_ERROR, "Your BVN details couldn't be found. Try again.")
                    logError(
                        "authenticate:Step 1: event_id: '%s' client_ref: '%s' bvn: '%s'. No details of the supplied BVN found." % (
                            identity.getSessionId().getId(), 
                            identity.getSessionId().getSessionAttributes().get("client_ref"), 
                            user_id
                        ),
                        LogCodes.API_CALL_FAIL
                    )
                    self.setRequestScopedParameters(identity, False)
                    return False
                else:
                    logInfo(
                        "authenticate:Step 1: User Inputed BVN found in BVN DB.Creating user based on BVN API data. Creating user. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                            identity.getSessionId().getId(), 
                            identity.getSessionId().getSessionAttributes().get("client_ref"), 
                            user_id
                            )
                    )
                    try:
                        isAdded = self.addUser(bvn_user, credentials.getUsername())
                        authenticated_user = self.searchForBvnUser(credentials)
                        if not authenticated_user:
                            logError(
                                "authenticate:Step 1: event_id: '%s' client_ref: '%s' bvn: '%s'. Could not authN the user with supplied BVN found." % (
                                    identity.getSessionId().getId(), 
                                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                                    user_id
                                ),
                                LogCodes.LOGIN_FAILED
                            )
                            #facesMessages.add(FacesMessage.SEVERITY_ERROR, "Your BVN details couldn't be found. Try again.")
                            self.setMessageError(FacesMessage.SEVERITY_ERROR, "Your BVN details couldn't be found. Try again.")
                            return False
                    except:
                        logError(
                            "authenticate:Step 1: event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to call BVN API dUe to exception '%s' with message: '%s' and trace: '%s'." % (
                                identity.getSessionId().getId(), 
                                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                                user_id,
                                sys.exc_info()[0],
                                sys.exc_info()[1],
                                traceback.format_tb(sys.exc_info()[2])[-1]
                            ),
                            LogCodes.LOGIN_FAILED
                        )
                        #facesMessages.add(FacesMessage.SEVERITY_ERROR, "Something went wrong! Try again.")
                        self.setMessageError(FacesMessage.SEVERITY_ERROR, "Something went wrong! Try again.")
                        return False
                    
            user_contacts = ArrayList(self.getAvailContactInf(authenticated_user)) 
            
            if len(user_contacts) < 1:
                return False
            
            otp_auth_method = "select"
            identity.setWorkingParameter("otp_auth_method", otp_auth_method)

            return True
        
        elif step == 2:
            authenticationService = CdiUtil.bean(AuthenticationService)
            user = authenticationService.getAuthenticatedUser()
            phoneNumInput = False
            address = None
            code = None
            if user == None:
                logError(
                            "authenticate:Step 2: event_id: '%s' client_ref: '%s' bvn: '%s'.Failed to determine user from session." % (
                                identity.getSessionId().getId(), 
                                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                                identity.getSessionId().getSessionAttributes().get("auth_user")
                            ),
                            LogCodes.LOGIN_FAILED
                        )
                return False
            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False
            alter = ServerUtil.getFirstValue(requestParameters, "alternativeMethod")
            if alter != None:
                # Bypass the rest of this step if an alternative address method was provided. Current step will be retried (see getNextStep)
                # Generate Random six digit code and store it in array
                if '*' not in alter:
                    phoneNumInput = True 
                    address = alter
                    isValid, msg = self.fetchIcadDetails(identity.getSessionId().getSessionAttributes().get("auth_user"), identity, alter)
                    if not isValid:
                        self.setMessageError(FacesMessage.SEVERITY_ERROR, msg)
                        identity.setWorkingParameter("retry_current_step", True)
                        otp_auth_method = "authenticate"
                        identity.setWorkingParameter("otp_auth_method", otp_auth_method)
                        return True
               
                #For performance testing we have to check if  self.otp_type is set to static
                if  self.otp_type == 'static':
                    code = "111111"
                else:
                    code = random.randint(100000, 999999)
                identity.getSessionId().getSessionAttributes().put("code", code)
                notAfter = datetime.now()+ timedelta(seconds=int(self.otp_ttl))
                identity.getSessionId().getSessionAttributes().put("code_notAfter", self.timestamp(notAfter))
                
                check = "@"
                channel = None
                """_summary_
                FIXING:Traceback (most recent call last):
                File "otp.py", line 217, in authenticate
                KeyError: u'2347***5171'
                Raises:
                    Exception: _description_
                    Exception: _description_

                Returns:
                    _type_: _description_
                """
                if not phoneNumInput:
                    contact_dict = identity.getSessionId().getSessionAttributes().get("hidden_contacts")
                    if (contact_dict != None):
                        try:
                            address = contact_dict[alter]
                        except KeyError:
                            logError(
                                "authenticate:Step 2: event_id: '%s' client_ref: '%s' bvn: '%s'.KeyError.Failed to determine contact value from key: '%s' from dictionary: '%s'." % (
                                    identity.getSessionId().getId(), 
                                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                                    identity.getSessionId().getSessionAttributes().get("auth_user"),
                                    alter,
                                    json.dumps(dict(contact_dict))
                                ),
                                LogCodes.CONTACT_INFO_FAIL
                            )
                            #facesMessages.add(FacesMessage.SEVERITY_ERROR, LogCodes.CONTACT_INFO_FAIL)
                            self.setMessageError(FacesMessage.SEVERITY_ERROR, LogCodes.CONTACT_INFO_FAIL)
                            return False
                
                if check in address:
                    status, response = self.sendEmail(code, address, identity)
                    if not status:
                        self.setMessageError(FacesMessage.SEVERITY_ERROR, response)
                    else:
                        channel = "email"
                else:
                    status, response = self.sendSMS(address, code, identity)
                    if not status:
                        self.setMessageError(FacesMessage.SEVERITY_ERROR, response)
                        logInfo(
                            "authenticate: step2. sendSms response: '%s' " % (
                            response
                            )
                        )
                    else:
                        channel = "sms"
                identity.setWorkingParameter("retry_current_step", True)
                otp_auth_method = "authenticate"
                identity.setWorkingParameter("otp_auth_method", otp_auth_method)
                if channel != None:
                    msg = "A 6-digit code has been sent to " + alter + " ."
                    identity.setWorkingParameter("msg", msg)
                return True
            # Restore state from session
            identity.setWorkingParameter("retry_current_step", False)
            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            otp_auth_result = self.processOtpAuthentication(requestParameters, identity)
            if (otp_auth_result):
                identity.getSessionId().getSessionAttributes().put("_tx_id", identity.getSessionId().getId())
                identity.getSessionId().getSessionAttributes().put("_remote_ip", self._remote_ip)
                identity.getSessionId().getSessionAttributes().put("_city", self._city)
                identity.getSessionId().getSessionAttributes().put("_country", self._country)
                sessionIdService = CdiUtil.bean(SessionIdService)
                sessionId = identity.getSessionId()
                sessionIdService.updateSessionId(sessionId)
            return otp_auth_result
        
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        identity = CdiUtil.bean(Identity)

        print "Consent Script. Preparing for step 1...setRequestScopedParameters"
        self.setRequestScopedParameters(identity, False)

        if step == 1:
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.clear()
            client_ref = ServerUtil.getFirstValue(requestParameters, "state")
            if client_ref != None:
                identity.getSessionId().getSessionAttributes().put("client_ref", client_ref)
            session_attributes = identity.getSessionId().getSessionAttributes()
            
            # remote_ip is populated OOTB. Its a variable available OOTB
            if session_attributes.containsKey("remote_ip"):
                self._remote_ip = session_attributes.get("remote_ip")
                geodata = None
                """
                if StringHelper.isNotEmpty(self._remote_ip):
                    if ("," in self._remote_ip):
                        self._remote_ip = self._remote_ip.split(",")[0]
                        geodata = self.getGeolocation(self._remote_ip, identity)
                    else:
                        geodata = self.getGeolocation(self._remote_ip, identity)
                    if geodata != None:
                        self._city = geodata['city']
                        self._country = geodata['country']
                """
            print "{\"logtype\":\"consent_requested\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\", \"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                session_attributes.get("client_id"), 
                session_attributes.get("client_name"), 
                self._remote_ip, 
                self._city, 
                self._country, 
                identity.getSessionId().getSessionAttributes().get("auth_user"), 
                datetime.now()
                )

            return True
        elif step == 2:
            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            authenticationService = CdiUtil.bean(AuthenticationService)
            user = authenticationService.getAuthenticatedUser()

            user_contacts = ArrayList(self.getAvailContactInf(user)) 
            data ={}
            if len(user_contacts) > 0:
                contacts = HashSet()
                
                for c in user_contacts:
                    x = c.split(":")[0]
                    contacts.add(x)
                    data[x]=c.split(":")[1]
            else:
                return False

            identity.setWorkingParameter("contacts", contacts)
            #issue with rendering icons. So using backend to set html tags
            for index, c in  enumerate(user_contacts, start=0):
                x = c.split(":")[0]
                if('@' in x):
                    identity.setWorkingParameter(x, "email")
                else:
                    identity.setWorkingParameter(x, "sms"+str(index))
            
            identity.getSessionId().getSessionAttributes().put("hidden_contacts", data)

            return True

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("otp_auth_method", "msg","retry_current_step", "contacts", "hidden_contacts", "client_ref", "code" )

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 2

    def setRequestScopedParameters(self, identity, notPrepareStep):
        client = self.setUpClientInfo(identity)
        if(client == None):
            return False
        
        if(notPrepareStep):
            authenticationService = CdiUtil.bean(AuthenticationService)
            user = authenticationService.getAuthenticatedUser()

            user_contacts = ArrayList(self.getAvailContactInf(user)) 
            data ={}
            if len(user_contacts) > 0:
                contacts = HashSet()
                
                for c in user_contacts:
                    x = c.split(":")[0]
                    contacts.add(x)
                    data[x]=c.split(":")[1]
                identity.setWorkingParameter("contacts", contacts)
                #issue with rendering icons. So using backend to set html tags
                for index, c in  enumerate(user_contacts, start=0):
                    x = c.split(":")[0]
                    if('@' in x):
                        identity.setWorkingParameter(x, "email")
                    else:
                        identity.setWorkingParameter(x, "sms"+str(index))
            
                identity.getSessionId().getSessionAttributes().put("hidden_contacts", data)

    def getPageForStep(self, configurationAttributes, step):
        if step == 1:
            return "/verify.xhtml"
        elif step == 2:
            return "/ext/otp.xhtml"

        return ""


    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Get external logout URL call"
        return None

    def logout(self, configurationAttributes, requestParameters):
        return True

    def processBasicAuthentication(self, credentials):
        userService = CdiUtil.bean(UserService)
        authenticationService = CdiUtil.bean(AuthenticationService)

        user_name = credentials.getUsername()
        user_password = credentials.getPassword()

        logged_in = False
        if StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password):
            logged_in = authenticationService.authenticate(user_name, user_password)

        if not logged_in:
            return None

        find_user_by_uid = authenticationService.getAuthenticatedUser()
        if find_user_by_uid == None:
            print "OTP. Process basic authentication. Failed to find user '%s'" % user_name
            return None
        
        return find_user_by_uid

    def validateSessionId(self, identity):
        session = CdiUtil.bean(SessionIdService).getSessionId()
        if session == None:
            logError(
                    "validateSessionId: event_id: '%s' client_ref: '%s' bvn: '%s'.Failed to determine session_id." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user")
                    ),
                    LogCodes.LOGIN_FAILED
                )
            return False

        otp_auth_method = identity.getWorkingParameter("otp_auth_method")
        if not otp_auth_method in ['select', 'authenticate']:
            logError(
                    "validateSessionId: event_id: '%s' client_ref: '%s' bvn: '%s'.Failed to determine otp_auth_method: '%s'"  % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        otp_auth_method
                    ),
                    LogCodes.LOGIN_FAILED
                )
            return False

        return True

    def processOtpAuthentication(self, requestParameters, user_name, identity, otp_auth_method):
        #facesMessages = CdiUtil.bean(FacesMessages)
        #facesMessages.setKeepMessages()

        code = identity.getSessionId().getSessionAttributes().get("code")
        otpCode = ServerUtil.getFirstValue(requestParameters, "loginForm:otpCode")

        if StringHelper.isEmpty(str(otpCode)):
            #facesMessages.add(FacesMessage.SEVERITY_INFO, "You did not supply a one time code")
            self.setMessageError(FacesMessage.SEVERITY_ERROR, LogCodes.OTP_VALIDATION_FAIL)
            logInfo(
                "processOtpAuthentication: User did not supply one time code. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    identity.getSessionId().getSessionAttributes().get("auth_user")
                    ),
                LogCodes.LOGIN_FAILED
            )
            return False

        # Validate TOTP
        now_in_secs = self.timestamp(datetime.now())
        if  now_in_secs < identity.getSessionId().getSessionAttributes().get("code_notAfter"):
            if str(otpCode) == str(code):
                logInfo(
                    "processOtpAuthentication: Successfully authn user with otp. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user")
                        ),
                    LogCodes.LOGIN_SUCCESSFUL
                )
                return True
        else:
            #facesMessages.add(FacesMessage.SEVERITY_INFO, "The one time code sent earlier has expired. Please create a new one")
            self.setMessageError(FacesMessage.SEVERITY_ERROR, LogCodes.OTP_VALIDATION_FAIL)
            self.setRequestScopedParameters(identity, True)
            logInfo(
                    "processOtpAuthentication: The one time code supplied has expired. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user")
                        ),
                    LogCodes.LOGIN_FAILED
                )
            return False
        #acesMessages.add(FacesMessage.SEVERITY_INFO, "Incorrect OTP. Try again or click below to resend.")
        self.setMessageError(FacesMessage.SEVERITY_ERROR, LogCodes.OTP_VALIDATION_FAIL)
        logInfo(
                "processOtpAuthentication: Incorrect one time code supplied by user. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    identity.getSessionId().getSessionAttributes().get("auth_user")
                    ),
                LogCodes.LOGIN_FAILED
            )
        self.setRequestScopedParameters(identity, True)
        return False

    def fetchUserFromBVNApi(self, user_name, identity):
        logInfo(
            "fetchUserFromBVNApi. event_id: '%s' client_ref: '%s' bvn: '%s'." % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                user_name
                )
        )
        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()
        http_client_params.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 15 * 1000)
        
        bvn_service_headers = { "Content-Type" : "application/json", "Accept" : "*/*", "x-consumer-custom-id" : str(self.x_consumer_custom_id), "x-consumer-unique-id" : str(self.x_consumer_unique_id) }
        bvn_service_postData = "['email','Phone_number1','phone_number2','surname','first_name','gender','date_of_birth','nationality','enrollment_date','title','enroll_user_name']"
         
        try:
            uri = str(self.api_host + "/internal-bvnretrieval/getDetailsWithBvn?bvn=" + user_name)
            http_service_response = httpService.executePost(http_client,uri , str(self.x_consumer_unique_id),  bvn_service_headers, str(bvn_service_postData))
            http_response = http_service_response.getHttpResponse()
        except:
            logError(
                    "fetchUserFromBVNApi. event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to call BVN API due to exception '%s' with message: '%s' and trace: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.API_CALL_FAIL
                )
            return None

        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                logError(
                    "fetchUserFromBVNApi. event_id: '%s' client_ref: '%s' bvn: '%s'. Recieved invalid response from BVN API. Response: '%s'" % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        str(http_response)
                    ),
                    LogCodes.PROFILE_LOOKUP_FAIL
                )
                httpService.consume(http_response)
                return None
    
            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes)
            httpService.consume(http_response)
        finally:
            http_service_response.closeConnection()

        if response_string == None:
            logError(
                    "fetchUserFromBVNApi. event_id: '%s' client_ref: '%s' bvn: '%s'. Recieved empty response from BVN API." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name
                    ),
                    LogCodes.PROFILE_LOOKUP_FAIL
                )
            return None
        response = json.loads(response_string.replace(']','').replace('[',''))
        try:
            enrolled_username = response['enroll_user_name']
            if enrolled_username is not None:
                logInfo(
                    "fetchUserFromBVNApi. event_id: '%s' client_ref: '%s' bvn: '%s' enroll_user_name: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        str(response['enroll_user_name'])
                        )
                )
                return response
        except:
            logError(
                    "fetchUserFromBVNApi. event_id: '%s' client_ref: '%s' bvn: '%s'. Cannot get data elements from response payload." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name
                    ),
                    LogCodes.PROFILE_LOOKUP_FAIL
                )
            return None


    def addUser(self, profile, bvn):
        """
        Function for account creation step. This step will create a new user on Gluu. If a failure is
        encountered then the user will be redirected back to the app.

        Returns:
            User if the step succeeded, or False otherwise.
        """
        newUser = User()
        userService = CdiUtil.bean(UserService)

        #Fill user attrs
        newUser.setAttribute("uid", bvn)
        newUser.setAttribute("displayName", profile['first_name']+ " " +profile['surname'])
        final_usr = self.fillUser(newUser, profile)
        created = userService.addUser(final_usr, True)
        return created

    def fillUser(self, user, profile):
        for attr in profile:
            values = profile[attr]
            
            if attr == "email":
                oxtrustMails = []
                #for mail in values:
                oxtrustMails.append('{"value":"%s","primary":false}' % values)
                user.setAttribute("oxTrustEmail", oxtrustMails)
                user.setAttribute("mail", values)

            elif attr == "surname":
                user.setAttribute("sn", values)

            elif attr == "first_name":
                user.setAttribute("givenName", values)
            
            elif attr == "Phone_number1":
                user.setAttribute("mobile", values)

            elif attr == "phone_number2":
                user.setAttribute("telephoneNumber", values)
            """
            elif attr == "title":
                user.setAttribute("title", values)
            
            elif attr == "enroll_user_name":
                user.setAttribute("preferredUsername", values)
           
            elif attr == "nationality":
                user.setAttribute("l", values)

            elif attr == "residential_address":
                user.setAttribute("homePostalAddress", values)
           
            elif attr == "gender":
                user.setAttribute("gender", values.lower())
             """
        logInfo("fillUser:Profile mapping done for user with bvn: %s" % user.getAttribute("uid"))
        return user

    def getAvailContactInf(self, user):
        contacts = HashSet()
        identity = CdiUtil.bean(Identity)
        try:
            email_address = user.getAttribute("mail")
            mobile_number = user.getAttribute("mobile")
            mobile_number2 = user.getAttribute("telephoneNumber")
            if mobile_number == None and mobile_number2 == None and email_address == None:
                raise Exception("addresses to send otp not found")
            else:
                if mobile_number2 != None:
                    contacts.add(self.getMaskedNumber(mobile_number2)+":"+mobile_number2)
                if mobile_number != None:
                   contacts.add(self.getMaskedNumber(mobile_number)+":"+mobile_number)
                if email_address != None:
                   contacts.add(self.getMaskedNumber(email_address)+":"+email_address)
        except:
            #facesMessages = CdiUtil.bean(FacesMessages)
            #facesMessages.add(FacesMessage.SEVERITY_ERROR, "Your contact details are incomplete. Please contact our helpdesk.")
            self.setMessageError(FacesMessage.SEVERITY_ERROR, "Your contact details are incomplete. Please contact our helpdesk.")
            logError(
                    "getAvailContactInf. event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to find contact details due to exception '%s' with message: '%s' and trace: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.LOGIN_FAILED
                )
        """
        logInfo(
            "getAvailContactInf: Contact details found. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                identity.getSessionId().getSessionAttributes().get("auth_user")
                )
        )
        """
        return contacts

    def getMaskedMail(self, s):
        c = s.split('@')
        d = c[0]
        e = c[1]
        a=list(d.strip())
        b="AEIOUaeiou"
        for i in range(len(a)):
            if a[i] in b:
                  a[i]='*'
            elif a[i].isdigit():
                 a[i]='*'
        return ("".join(a) + '@'+e)

    def getMaskedNumber(self, s):
        if (s != None and len(s) > 7):
            sub = s[4:7]

        return s.replace(sub,"***")

    def sendSMS(self, destination, code, identity):
        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()
        http_client_params.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 15 * 1000)
       
        sms_service_headers = { "Content-Type" : "application/json", "Accept" : "*/*"}
        payload = json.dumps({
            "smsSubject": "BVNID",
            "smsMessage": "Your One Time Temporary Pin is: %s. This code will expire in 10 mins. Do not share with anyone. info@nibss-plc.com.ng"% (code),
            "receiverMobileNumber": " %s" % (destination),
            "senderMobileNumber": "NIBSS",
            "TransactionId":" %s"% (identity.getSessionId().getId())
            })
        
        try:
            sms_url = self.api_host+"/internal-sms"
            http_service_response = httpService.executePost(http_client,sms_url, str(self.x_consumer_unique_id),  sms_service_headers, str(payload))
            if http_service_response == None:
                print "{\"logtype\":\"sms_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"failed\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    identity.getSessionId().getSessionAttributes().get("client_id"), 
                    identity.getSessionId().getSessionAttributes().get("client_name"), 
                    self._remote_ip, 
                    self._city, 
                    self._country, 
                    identity.getSessionId().getSessionAttributes().get("auth_user"), 
                    datetime.now()
                    )
                logError(
                    "sendSMS. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'. Failed to call SMS API due to network connection failure: uri:'%s' ." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        destination,
                        sms_url
                    ),
                    LogCodes.API_CALL_FAIL
                )
                return False, LogCodes.OTP_DELIVERY_FAIL
            http_response = http_service_response.getHttpResponse()
        except:
            logError(
                    "sendSMS. event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to send SMS due to exception '%s' with message: '%s' and trace: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.API_CALL_FAIL
                )
            print "{\"logtype\":\"sms_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"failed\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                identity.getSessionId().getSessionAttributes().get("client_id"),
                identity.getSessionId().getSessionAttributes().get("client_name"), 
                self._remote_ip, 
                self._city, 
                self._country, 
                identity.getSessionId().getSessionAttributes().get("auth_user"), 
                datetime.now()
                )
            return False, LogCodes.OTP_DELIVERY_FAIL
        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                logError(
                    "sendSMS. event_id: '%s' client_ref: '%s' bvn: '%s'. received invalid response: Status: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        str(http_response.getStatusLine().getStatusCode())
                    ),
                    LogCodes.API_CALL_FAIL
                )
                httpService.consume(http_response)
                print "{\"logtype\":\"sms_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"failed\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    identity.getSessionId().getSessionAttributes().get("client_id"), 
                    identity.getSessionId().getSessionAttributes().get("client_name"), 
                    self._remote_ip, 
                    self._city, 
                    self._country, 
                    identity.getSessionId().getSessionAttributes().get("auth_user"), 
                    datetime.now()
                    )
                return False, LogCodes.OTP_DELIVERY_FAIL
    
            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes)
            httpService.consume(http_response)
        finally:
            http_service_response.closeConnection()

        if response_string == None:
            logError(
                    "sendSMS. event_id: '%s' client_ref: '%s' bvn: '%s'. received empty response." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user")
                    ),
                    LogCodes.API_CALL_FAIL
                )
            print "{\"logtype\":\"sms_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"failed\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                identity.getSessionId().getSessionAttributes().get("client_id"), 
                identity.getSessionId().getSessionAttributes().get("client_name"), 
                self._remote_ip, 
                self._city, 
                self._country, 
                identity.getSessionId().getSessionAttributes().get("auth_user"), 
                datetime.now()
                )
            return False, LogCodes.OTP_DELIVERY_FAIL
        
        print "{\"logtype\":\"sms_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"success\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
            identity.getSessionId().getId(), 
            identity.getSessionId().getSessionAttributes().get("client_ref"), 
            identity.getSessionId().getSessionAttributes().get("client_id"), 
            identity.getSessionId().getSessionAttributes().get("client_name"), 
            self._remote_ip, 
            self._city, 
            self._country, 
            identity.getSessionId().getSessionAttributes().get("auth_user"), 
            datetime.now()
            )
        return True, LogCodes.API_CALL_SUCCESS

    def sendEmail(self, code, addy, identity):

        try:
            mailService = CdiUtil.bean(MailService)
            subject = "BVNID OTP %s" % (code)
            body = "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'https://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\
                <html xmlns='https://www.w3.org/1999/xhtml' lang='en' xml:lang='en'\
                xmlns:v='urn:schemas-microsoft-com:vml'\
                xmlns:o='urn:schemas-microsoft-com:office:office'>"
            body += "<head> <meta name='viewport' content='width=device-width, initial-scale=1.0'>\
            <link href='https://fonts.cdnfonts.com/css/gotham' rel='stylesheet' /></head>"
            body += "<body style='font-family:Gotham; position: relative; color: #5d6975;'>"
            body += "<div style='max-width: 600px; height: 100%; text-align: center; margin: 0 auto; position: relative;' class='container mx-auto'>"
            body += "<p style='padding: 20px;' class='email-header-image'><img style='width: 180px; padding-bottom: 20px;' src='https://id.nibss-plc.com.ng/oxauth/ext/resources/images/nibss.webp'></p>\
                <div style='background-size: contain !important; background-position: center !important; background: url(\"https://id.nibss-plc.com.ng/oxauth/ext/resources/images/nibss_email_bg.png\") no-repeat;'>"
            body += "<p style='color: #5d6975; font-size: 24px; font-weight: bold; line-height: 1.8rem;'>Your One Time Temporary Pin is</p>\
                <p style='color: green; font-size: 24px; font-weight: bold; line-height: 1.8rem;'>%s</p>\
                <p style='font-weight: bold; font-size: 1rem; line-height: 1.2rem;'>This code will expire in 10 mins</p>" % (code)  
            body +="<p style='font-size: 1rem; line-height: 1.8rem;'>You received this code because <strong>%s</strong> has requested some information about you.</p>\
                <p style='color: #5d6975; font-size: 1.5rem; font-weight: bold; line-height: 3rem; text-align:center;'>Do not share with anyone.</p>" % (identity.getSessionId().getSessionAttributes().get("client_name")) 
            body +="<p style='font-size: 1rem; line-height: 1.5rem; padding: 12px;'>\
                If this is not you accessing our online services, please contact us.</p>\
                </div>\
                    <p style='text-align: center;display: block;line-height: 2rem;margin-top: 5px;'>\
                <p style='color: #5d6975; display: inline-block; text-decoration: none; font-size: 14px;padding: 5px;'>NIBSS Contact Centre: 07000 500 000</p>\
                <a style='color: #5d6975; text-decoration: none;display: inline-block;font-size: 14px;padding: 5px;' href='mailto:info@nibss-plc.com.ng'>info@nibss-plc.com.ng</a>\
                </p>\
                <p style='text-align: center;display: block;line-height: 2rem;margin-top: 50px;'>\
                <a style='color: #5d6975; display: inline-block; text-decoration: none; font-size: 14px;padding: 5px;' href='https://nibss-plc.com.ng/policy/privacy-policy'>Privacy Policy</a>\
                <a style='color: #5d6975; text-decoration: none;display: inline-block;font-size: 14px;padding: 5px;' href='https://nibss-plc.com.ng/services/terms-of-use/'>Terms of Services</a>\
                </p>"
            body += "</div></body> </html>"
            #sent = False
            sent = mailService.sendMail(addy, None, subject, body, body);
            if sent:
                print "{\"logtype\":\"email_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"success\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"),  
                    identity.getSessionId().getSessionAttributes().get("client_id"), 
                    identity.getSessionId().getSessionAttributes().get("client_name"), 
                    self._remote_ip, 
                    self._city, 
                    self._country, 
                    identity.getSessionId().getSessionAttributes().get("auth_user"), 
                    datetime.now()
                    )
                return True, LogCodes.API_CALL_SUCCESS
            else:
                print "{\"logtype\":\"email_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"failed\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    identity.getSessionId().getSessionAttributes().get("client_id"), 
                    identity.getSessionId().getSessionAttributes().get("client_name"), 
                    self._remote_ip, 
                    self._city, 
                    self._country, 
                    identity.getSessionId().getSessionAttributes().get("auth_user"), 
                    datetime.now()
                    )
                return False, LogCodes.OTP_DELIVERY_FAIL
        except:
            logError(
                    "sendEmail. event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to send email due to exception '%s' with message: '%s' and trace: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.API_CALL_FAIL
                )
            print "{\"logtype\":\"email_dispatch\",\"event_id\": \"%s\",\"client_ref\": \"'%s'\",\"status\":\"failed\",\"client_id\": \"%s\",\"client_name\": \"%s\",\"remote_ip\": \"%s\",\"city\": \"%s\",\"country\": \"%s\",\"bvn\": \"%s\",\"timestamp\":\"%s\"}" % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                identity.getSessionId().getSessionAttributes().get("client_id"), 
                identity.getSessionId().getSessionAttributes().get("client_name"), 
                self._remote_ip, 
                self._city, 
                self._country, 
                identity.getSessionId().getSessionAttributes().get("auth_user"), 
                datetime.now()
                )
            return False, LogCodes.OTP_DELIVERY_FAIL
    

    def setUpClientInfo(self, identity):
        # Get client configuration
        clientId = identity.getSessionId().getSessionAttributes().get("client_id")      
        if (clientId == None):
            return None
        clientService = CdiUtil.bean(ClientService)
        client = clientService.getClient(clientId)
        if (client == None):
            logError(
                    "setUpClientInfo. event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to find client '%s' in local LDAP." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        clientId
                    ),
                    LogCodes.LOGIN_FAILED
                )
            return None
        else:
            identity.getSessionId().getSessionAttributes().put("client_name", client.getClientName())
            #Setting the following for step 1
            identity.setWorkingParameter("client_id", client.getClientId())
            identity.setWorkingParameter("clientName", client.getClientName())
            identity.setWorkingParameter("policyURI", client.policyUri)
            identity.setWorkingParameter("logoURI", client.getLogoUri())
            identity.setWorkingParameter("tosURI", client.tosUri)
        return client

    def getGeolocation(self, remote_ip, identity):
        if StringHelper.isNotEmpty(remote_ip):
            httpService = CdiUtil.bean(HttpService)
            http_client = httpService.getHttpsClient()
            http_client_params = http_client.getParams()
            http_client_params.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 4 * 1000)

            geolocation_service_url = "http://ip-api.com/json/%s?fields=country,city,status,message" % remote_ip
            geolocation_service_headers = { "Accept" : "application/json" }

            try:
                http_service_response = httpService.executeGet(http_client, geolocation_service_url, geolocation_service_headers)
                http_response = http_service_response.getHttpResponse()
            except:
                logError(
                    "getGeolocation. event_id: '%s' client_ref: '%s' bvn: '%s'. Failed to determine remote location due to exception '%s' with message: '%s' and trace: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user"),
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.API_CALL_FAIL
                )
                return None

            try:
                if not httpService.isResponseStastusCodeOk(http_response):
                    logError(
                        "getGeolocation. event_id: '%s' client_ref: '%s' bvn: '%s'. Got a none 200 OK response from server: status code: '%s'." % (
                            identity.getSessionId().getId(), 
                            identity.getSessionId().getSessionAttributes().get("client_ref"), 
                            identity.getSessionId().getSessionAttributes().get("auth_user"),
                            str(http_response.getStatusLine().getStatusCode())
                        ),
                        LogCodes.API_CALL_FAIL
                        )
                    httpService.consume(http_response)
                    return None

                response_bytes = httpService.getResponseContent(http_response)
                response_string = httpService.convertEntityToString(response_bytes, Charset.forName("UTF-8"))
                httpService.consume(http_response)
            finally:
                http_service_response.closeConnection()

            if response_string == None:
                logError(
                    "getGeolocation. event_id: '%s' client_ref: '%s' bvn: '%s'. received empty response." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        identity.getSessionId().getSessionAttributes().get("auth_user")
                    ),
                    LogCodes.API_CALL_FAIL
                )
                return None

            response = json.loads(response_string)

            if not StringHelper.equalsIgnoreCase(response['status'], "success"):
                logInfo("getGeolocation:Get response with status: %s" % response['status'])
                return None

            return response

        return None
    
    def timestamp(self, date):
        return time.mktime(date.timetuple())
    
    def fetchIcadDetails(self, user_name, identity, phoneNum):

        httpService = CdiUtil.bean(HttpService)

        http_client = httpService.getHttpsClient()
        http_client_params = http_client.getParams()
        http_client_params.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 15 * 1000)
        
        icad_service_headers = { "Content-Type" : "application/json", "Accept" : "*/*", "x-consumer-custom-id" : str(self.x_consumer_custom_id), "x-consumer-unique-id" : str(self.x_consumer_unique_id) }
        icad_service_postData = "[\"phonenumber\",\"phonenumber2\"]"
         
        try:
            uri = str(self.api_host + "/internal-bvnretrieval/getIcadPartialDetailsWithBVN?bvn="+user_name)
            http_service_response = httpService.executePost(http_client,uri, str(self.x_consumer_unique_id),  icad_service_headers, str(icad_service_postData))
            if http_service_response == None:
                logError(
                    "fetchIcadDetails. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'. Failed to call ICAD API due to network connection failure: uri:'%s' ." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        phoneNum,
                        uri
                    ),
                    LogCodes.API_CALL_FAIL
                )
                return False, LogCodes.OTP_DELIVERY_FAIL
            http_response = http_service_response.getHttpResponse()
        except:
            logError(
                    "fetchIcadDetails. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'. Failed to call ICAD API due to exception '%s' with message: '%s' and trace: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        phoneNum,
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.API_CALL_FAIL
                )
        try:
            if not httpService.isResponseStastusCodeOk(http_response):
                logError(
                    "fetchIcadDetails. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'. Recieved invalid response from ICAD API. Response: '%s'" % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        phoneNum,
                        str(http_response)
                    ),
                    LogCodes.PROFILE_LOOKUP_FAIL
                )
                httpService.consume(http_response)
                return False, LogCodes.OTP_DELIVERY_FAIL
    
            response_bytes = httpService.getResponseContent(http_response)
            response_string = httpService.convertEntityToString(response_bytes)
            httpService.consume(http_response)
        finally:
            
            http_service_response.closeConnection()

        if response_string == None:
            logError(
                    "fetchIcadDetails. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'. Recieved empty response from ICAD API." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        phoneNum
                    ),
                    LogCodes.PROFILE_LOOKUP_FAIL
                )
            return False, LogCodes.OTP_DELIVERY_FAIL
        try:
            response = json.loads(response_string)
            valid = self.isValidIcadNum(phoneNum, response, identity)
            if not valid:
                logInfo(
                    "fetchIcadDetails. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'. No matching number found." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        phoneNum
                        )
                )
                return False, LogCodes.OTP_NUM_ICAD_MATCH_FAIL
            else:
                return True, LogCodes.OTP_NUM_ICAD_MATCH_SUCCESS
        except:
            logError(
                    "fetchIcadDetails. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'. Failed to process ICAD API response due to exception '%s' with message: '%s' and trace: '%s'." % (
                        identity.getSessionId().getId(), 
                        identity.getSessionId().getSessionAttributes().get("client_ref"), 
                        user_name,
                        phoneNum,
                        sys.exc_info()[0],
                        sys.exc_info()[1],
                        traceback.format_tb(sys.exc_info()[2])[-1]
                    ),
                    LogCodes.API_CALL_FAIL
                )
            return False, LogCodes.OTP_DELIVERY_FAIL
    
    def setMessageError(self, severity, msg):
        facesMessages = CdiUtil.bean(FacesMessages)
        #facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(severity, msg)
    
    def isValidIcadNum(self, telNum, icadResponse, identity):
        tel = telNum.strip()[1:]
        for d in icadResponse:
            for key, value in d.iteritems():
                if tel in  value:
                    return True
        logInfo(
                "isValidIcadNum. No match. event_id: '%s' client_ref: '%s' bvn: '%s' phone: '%s'" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    identity.getSessionId().getSessionAttributes().get("auth_user"),
                    telNum
                    )
            )
        return False

    # Shared HOTP/TOTP methods
    # TOTP methods

    def searchForBvnUser(self, credentials):
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)
        user_name = credentials.getUsername()
        user_password = credentials.getPassword()
        print "Consent Script. Search on Flex for BVN userPWD: %s" % user_password
        logged_in = False
        """
        logInfo(
            "searchForBvnUser: Trying to authn the user on Gluu. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                user_name
                )
        )
        """
        if StringHelper.isNotEmptyString(user_name):
            logged_in = authenticationService.authenticate(user_name)

        if not logged_in:
            logInfo(
                "searchForBvnUser: Failed to authn the user on Gluu. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    user_name
                    )
            )
            return None

        find_user_by_uid = authenticationService.getAuthenticatedUser()
        if find_user_by_uid == None:
            logInfo(
                "searchForBvnUser: Failed to find the user on Gluu. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                    identity.getSessionId().getId(), 
                    identity.getSessionId().getSessionAttributes().get("client_ref"), 
                    user_name
                    ),
                LogCodes.LOGIN_SUCCESSFUL
            )
            return None
        logInfo(
            "searchForBvnUser: Successfully found the user on Gluu. event_id: '%s' client_ref: '%s' bvn: '%s'" % (
                identity.getSessionId().getId(), 
                identity.getSessionId().getSessionAttributes().get("client_ref"), 
                user_name
                )
        )
        return find_user_by_uid

    # Utility methods
#
