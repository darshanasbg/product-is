package org.wso2.identity.integration.test.oidc;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.opensaml.xml.util.Base64;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.automation.engine.context.AutomationContext;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.identity.application.common.model.idp.xsd.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.idp.xsd.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.idp.xsd.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.idp.xsd.Property;
import org.wso2.carbon.identity.application.common.model.xsd.*;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;
import org.wso2.identity.integration.common.clients.UserManagementClient;
import org.wso2.carbon.user.mgt.stub.UserAdminUserAdminException;
import org.wso2.identity.integration.common.clients.application.mgt.ApplicationManagementServiceClient;
import org.wso2.identity.integration.common.clients.oauth.OauthAdminClient;
import org.wso2.identity.integration.common.utils.ISIntegrationTest;
import org.wso2.identity.integration.test.application.mgt.AbstractIdentityFederationTestCase;
import org.wso2.identity.integration.test.oidc.bean.OIDCApplication;
import org.wso2.identity.integration.test.util.Utils;
import org.wso2.identity.integration.test.utils.CommonConstants;
import org.wso2.identity.integration.test.utils.IdentityConstants;
import org.wso2.identity.integration.test.utils.OAuth2Constant;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.*;


public class OIDCIdentityFederationTestCase extends AbstractIdentityFederationTestCase {


    private static final String PRIMARY_IS_SERVICE_PROVIDER_NAME = "travelocity";
    private static final String SECONDARY_IS_SERVICE_PROVIDER_NAME = "secondarySP";
    protected static final String IDENTITY_PROVIDER_NAME = "trustedIdP";
    private static final String PRIMARY_IS_SAML_ISSUER_NAME = "travelocity.com";
    private static final String PRIMARY_IS_SAML_ACS_URL = "http://localhost:8490/travelocity.com/home.jsp";
    private static final String SECONDARY_IS_SAML_ISSUER_NAME = "samlFedSP";
    private static final String SAML_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    private static final String SAML_SSO_URL = "http://localhost:8490/travelocity.com/samlsso?SAML2" +
                                               ".HTTPBinding=HTTP-Redirect";
    private static final String SAML_SSO_LOGOUT_URL = "http://localhost:8490/travelocity"
            + ".com/logout?SAML2.HTTPBinding=HTTP-Redirect";

    private static final String CALLBACK_URL = "https://localhost:9853/commonauth";

    private static final String USER_AGENT = "Apache-HttpClient/4.2.5 (java 1.5)";
    private static final String AUTHENTICATION_TYPE = "federated";
    private static final String INBOUND_AUTH_TYPE = "samlsso";
    private static final int TOMCAT_8490 = 8490;
    protected static final int PORT_OFFSET_0 = 0;
    private static final int PORT_OFFSET_1 = 1;
    private static final String OIDCAUTHENTICATOR = "OpenIDConnectAuthenticator";
    private String COMMON_AUTH_URL = "https://localhost:%s/commonauth";

    private String consumerKeyForPrimaryIS;
    private String consumerSecretForPrimaryIS;

    private String usrName = "testFederatedUser";
    private String usrPwd = "testFederatePassword";
    private String usrRole = "admin";

    //Claim Uris
    private static final String lastNameClaimURI = "http://wso2.org/claims/lastname";

    private static final String ATTRIBUTE_CS_INDEX_NAME_SP = "attrConsumServiceIndex";
    private static final String ATTRIBUTE_CS_INDEX_NAME_IDP = "AttributeConsumingServiceIndex";

    protected OauthAdminClient adminClient;
    //protected ApplicationManagementServiceClient appMgtclient;

    @BeforeClass(alwaysRun = true)
    public void initTest() throws Exception {

        super.initTest();
        adminClient = new OauthAdminClient(backendURL, sessionCookie);
        //appMgtclient = new ApplicationManagementServiceClient(sessionCookie, backendURL, null);

        Map<String, String> startupParameters = new HashMap<String, String>();
        startupParameters.put("-DportOffset", String.valueOf(PORT_OFFSET_1 + CommonConstants.IS_DEFAULT_OFFSET));
        AutomationContext context = new AutomationContext("IDENTITY", "identity002", TestUserMode.SUPER_TENANT_ADMIN);

        startCarbonServer(PORT_OFFSET_1, context, startupParameters);

        super.createServiceClients(PORT_OFFSET_0, sessionCookie, new IdentityConstants
                .ServiceClientType[]{IdentityConstants.ServiceClientType.APPLICATION_MANAGEMENT, IdentityConstants.ServiceClientType.IDENTITY_PROVIDER_MGT, IdentityConstants.ServiceClientType.SAML_SSO_CONFIG});
        super.createServiceClients(PORT_OFFSET_1, null, new IdentityConstants.ServiceClientType[]{IdentityConstants.ServiceClientType.APPLICATION_MANAGEMENT, IdentityConstants.ServiceClientType.OAUTH_ADMIN});
        //add new test user to secondary IS
        boolean userCreated = addUserToSecondaryIS();
        Assert.assertTrue(userCreated, "User creation failed");
    }

        private boolean addUserToSecondaryIS() throws Exception {
        UserManagementClient usrMgtClient = new UserManagementClient(getSecondaryISURI(), "admin", "admin");
        if (usrMgtClient == null) {
            return false;
        } else {
            String[] roles = {usrRole};
            usrMgtClient.addUser(usrName, usrPwd, roles, null);
            if (usrMgtClient.userNameExists(usrRole, usrName)) {
                return true;
            } else {
                return false;
            }
        }
    }

    @AfterClass(alwaysRun = true)
    public void endTest() throws Exception {

        super.deleteSAML2WebSSOConfiguration(PORT_OFFSET_0, PRIMARY_IS_SAML_ISSUER_NAME);
        super.deleteServiceProvider(PORT_OFFSET_0, PRIMARY_IS_SERVICE_PROVIDER_NAME);
        super.deleteIdentityProvider(PORT_OFFSET_0, IDENTITY_PROVIDER_NAME);

   //     super.deleteSAML2WebSSOConfiguration(PORT_OFFSET_1, SECONDARY_IS_SAML_ISSUER_NAME);
        super.deleteOIDCConfiguration(PORT_OFFSET_1, consumerKeyForPrimaryIS);
        super.deleteServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);

        //delete added users to secondary IS
        deleteAddedUsers();

        super.stopCarbonServer(PORT_OFFSET_1);
    }

    @Test(priority = 2, groups = "wso2.is", description = "Check create identity provider in primary IS")
    public void testCreateIdentityProviderInPrimaryIS() throws Exception {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName(IDENTITY_PROVIDER_NAME);

        FederatedAuthenticatorConfig oidcAuthnConfig = new FederatedAuthenticatorConfig();
        oidcAuthnConfig.setName(OIDCAUTHENTICATOR);
        oidcAuthnConfig.setDisplayName("openidconnect");
        oidcAuthnConfig.setEnabled(true);
        oidcAuthnConfig.setProperties(getOIDCAuthnConfigProperties());
        identityProvider.setDefaultAuthenticatorConfig(oidcAuthnConfig);
        identityProvider.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{oidcAuthnConfig});

        JustInTimeProvisioningConfig jitConfig = new JustInTimeProvisioningConfig();
        jitConfig.setProvisioningEnabled(true);
        jitConfig.setProvisioningUserStore("PRIMARY");
        identityProvider.setJustInTimeProvisioningConfig(jitConfig);

        super.addIdentityProvider(PORT_OFFSET_0, identityProvider);

        Assert.assertNotNull(getIdentityProvider(PORT_OFFSET_0, IDENTITY_PROVIDER_NAME), "Failed to create Identity Provider 'trustedIdP' in primary IS");
    }

    @Test(priority = 3, groups = "wso2.is", description = "Check create service provider in primary IS")
    public void testCreateServiceProviderInPrimaryIS() throws Exception {

//        super.addServiceProvider(PORT_OFFSET_0, PRIMARY_IS_SERVICE_PROVIDER_NAME);
//
//        ServiceProvider serviceProvider = getServiceProvider(PORT_OFFSET_0, PRIMARY_IS_SERVICE_PROVIDER_NAME);
//        Assert.assertNotNull(serviceProvider, "Failed to create service provider 'travelocity' in primary IS");
//
//        updateServiceProviderWithSAMLConfigs(PORT_OFFSET_0, PRIMARY_IS_SAML_ISSUER_NAME, PRIMARY_IS_SAML_ACS_URL, serviceProvider);
//
//        AuthenticationStep authStep = new AuthenticationStep();
//        org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider idP = new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider();
//        idP.setIdentityProviderName(IDENTITY_PROVIDER_NAME);
//        org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig oidcAuthnConfig = new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig();
//        oidcAuthnConfig.setName(OIDCAUTHENTICATOR);
//        oidcAuthnConfig.setDisplayName("openidconnect");
//        idP.setFederatedAuthenticatorConfigs(new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig[]{oidcAuthnConfig});
//        authStep.setFederatedIdentityProviders(new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider[]{idP});
//        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationSteps(new AuthenticationStep[]{authStep});
//        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationType(AUTHENTICATION_TYPE);
//
//        updateServiceProvider(PORT_OFFSET_0, serviceProvider);
//        serviceProvider = getServiceProvider(PORT_OFFSET_0, PRIMARY_IS_SERVICE_PROVIDER_NAME);
//
//        InboundAuthenticationRequestConfig[] configs = serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
//        boolean success = false;
//        if (configs != null) {
//            for (InboundAuthenticationRequestConfig config : configs) {
//                if (PRIMARY_IS_SAML_ISSUER_NAME.equals(config.getInboundAuthKey()) && INBOUND_AUTH_TYPE.equals(config.getInboundAuthType())) {
//                    success = true;
//                    break;
//                }
//            }
//        }
//
//        Assert.assertTrue(success, "Failed to update service provider with inbound SAML2 configs in primary IS");
//        Assert.assertTrue(AUTHENTICATION_TYPE.equals(serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationType()), "Failed to update local and out bound configs in primary IS");

        super.addServiceProvider(PORT_OFFSET_0, PRIMARY_IS_SERVICE_PROVIDER_NAME);

        ServiceProvider serviceProvider = getServiceProvider(PORT_OFFSET_0, PRIMARY_IS_SERVICE_PROVIDER_NAME);
        Assert.assertNotNull(serviceProvider, "Failed to create service provider 'travelocity' in primary IS");

        updateServiceProviderWithSAMLConfigs(PORT_OFFSET_0, PRIMARY_IS_SAML_ISSUER_NAME, PRIMARY_IS_SAML_ACS_URL, serviceProvider);

        AuthenticationStep authStep = new AuthenticationStep();
        org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider idP = new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider();
        //IdentityProvider idp = super.getIdentityProvider(PORT_OFFSET_0, OIDCAUTHENTICATOR);
        idP.setIdentityProviderName(IDENTITY_PROVIDER_NAME);
        org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig oidcAuthnConfig = new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig();
        oidcAuthnConfig.setName(OIDCAUTHENTICATOR);
        oidcAuthnConfig.setDisplayName("openidconnect");
        idP.setFederatedAuthenticatorConfigs(new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig[]{oidcAuthnConfig});
        authStep.setFederatedIdentityProviders(new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider[]{idP});
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationSteps(new AuthenticationStep[]{authStep});
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationType(AUTHENTICATION_TYPE);

        updateServiceProvider(PORT_OFFSET_0, serviceProvider);
        serviceProvider = getServiceProvider(PORT_OFFSET_0, PRIMARY_IS_SERVICE_PROVIDER_NAME);

        InboundAuthenticationRequestConfig[] configs = serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
        boolean success = false;
        if (configs != null) {
            for (InboundAuthenticationRequestConfig config : configs) {
                if (INBOUND_AUTH_TYPE.equals(config.getInboundAuthType())) {
                    success = true;
                    break;
                }
            }
        }

        Assert.assertTrue(success, "Failed to update service provider with inbound SAML2 configs in primary IS");
        Assert.assertTrue(AUTHENTICATION_TYPE.equals(serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationType()), "Failed to update local and out bound configs in primary IS");
    }

    @Test(priority = 1, groups = "wso2.is", description = "Check create service provider in secondary IS")
    public void testCreateServiceProviderInSecondaryIS() throws Exception {

        super.addServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);

        ServiceProvider serviceProvider = getServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);
        Assert.assertNotNull(serviceProvider, "Failed to create service provider 'secondarySP' in secondary IS");

        //updateServiceProviderWithSAMLConfigs(PORT_OFFSET_1, SECONDARY_IS_SAML_ISSUER_NAME, String.format(COMMON_AUTH_URL, DEFAULT_PORT + PORT_OFFSET_0), serviceProvider);



        updateServiceProviderWithOIDCConfigs(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME, CALLBACK_URL, serviceProvider);

        //serviceProvider = appMgtclient.getApplication(SECONDARY_IS_SERVICE_PROVIDER_NAME);

        super.updateServiceProvider(PORT_OFFSET_1, serviceProvider);
        serviceProvider = getServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);

        InboundAuthenticationRequestConfig[] configs = serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
        boolean success = false;
        if (configs != null) {
            for (InboundAuthenticationRequestConfig config : configs) {
                if (consumerKeyForPrimaryIS.equals(config.getInboundAuthKey()) && OAuth2Constant.OAUTH_2.equals(config.getInboundAuthType())) {
                    success = true;
                    break;
                }
            }
        }

        Assert.assertTrue(success, "Failed to update service provider with inbound OIDC configs in secondary IS");
    }

    @Test(priority = 4, groups = "wso2.is", description = "Check create service provider in secondary IS")
    public void testFederation() throws Exception {
        HttpClient client = new DefaultHttpClient();

        String sessionId = sendSAMLRequestToPrimaryIS(client);
        Assert.assertNotNull(sessionId, "Unable to acquire 'sessionDataKey' value");

        String redirectURL = authenticateWithSecondaryIS(client, sessionId);
        Assert.assertNotNull(redirectURL, "Unable to acquire redirect url after login to secondary IS");

        Map<String, String> responseParameters = getOIDCResponseFromSecondaryIS(client, redirectURL);
        Assert.assertNotNull(responseParameters);
//        Assert.assertNotNull(responseParameters.get("SAMLResponse"), "Unable to acquire 'SAMLResponse' value");
//        Assert.assertNotNull(responseParameters.get("RelayState"), "Unable to acquire 'RelayState' value");

//        redirectURL = sendSAMLResponseToPrimaryIS(client, responseParameters);
//        Assert.assertNotNull(redirectURL, "Unable to acquire redirect url after sending SAML response to primary IS");
//
//        String samlResponse = getSAMLResponseFromPrimaryIS(client, redirectURL);
//        Assert.assertNotNull(samlResponse, "Unable to acquire SAML response from primary IS");
//
//        String decodedSAMLResponse = new String(Base64.decode(samlResponse));
//        Assert.assertTrue(decodedSAMLResponse.contains("AuthnContextClassRef"), "AuthnContextClassRef is not received" +
//                ".");
//        Assert.assertTrue(decodedSAMLResponse.contains("AuthenticatingAuthority"), "AuthenticatingAuthority is not " +
//                "received.");
//
//        boolean validResponse = sendSAMLResponseToWebApp(client, samlResponse);
//        Assert.assertTrue(validResponse, "Invalid SAML response received by travelocity app");

    }

    protected String getSecondaryISURI() {
        return String.format("https://localhost:%s/services/", DEFAULT_PORT + PORT_OFFSET_1);
    }

    private String sendSAMLRequestToPrimaryIS(HttpClient client) throws Exception {

        HttpGet request = new HttpGet(SAML_SSO_URL);
        request.addHeader("User-Agent", USER_AGENT);
        HttpResponse response = client.execute(request);
        return extractValueFromResponse(response, "name=\"sessionDataKey\"", 1);
    }

    private String authenticateWithSecondaryIS(HttpClient client, String sessionId)
            throws Exception {

        HttpPost request = new HttpPost(String.format(COMMON_AUTH_URL, DEFAULT_PORT + PORT_OFFSET_1));
        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Referer", PRIMARY_IS_SAML_ACS_URL);

        List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
        urlParameters.add(new BasicNameValuePair("username", usrName));
        urlParameters.add(new BasicNameValuePair("password", usrPwd));
        urlParameters.add(new BasicNameValuePair("sessionDataKey", sessionId));
        request.setEntity(new UrlEncodedFormEntity(urlParameters));

        HttpResponse response = client.execute(request);
        String locationHeader = getHeaderValue(response, "Location");
        if (Utils.requestMissingClaims(response)) {
            String pastrCookie = Utils.getPastreCookie(response);
            Assert.assertNotNull(pastrCookie, "pastr cookie not found in response.");
            EntityUtils.consume(response.getEntity());

            response = Utils.sendPOSTConsentMessage(response, String.format(COMMON_AUTH_URL, DEFAULT_PORT +
                            PORT_OFFSET_1), USER_AGENT , locationHeader, client, pastrCookie);
            EntityUtils.consume(response.getEntity());
            locationHeader = getHeaderValue(response, "Location");
        }
        closeHttpConnection(response);

        return locationHeader;
    }

        private Map<String, String> getOIDCResponseFromSecondaryIS(HttpClient client, String redirectURL) throws Exception {

        HttpPost request = new HttpPost(redirectURL);
        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Referer", PRIMARY_IS_SAML_ACS_URL);
        HttpResponse response = client.execute(request);

        Map<String, Integer> searchParams = new HashMap<String, Integer>();
        searchParams.put("SAMLResponse", 5);
        searchParams.put("RelayState", 5);
        return extractValuesFromResponse(response, searchParams);
    }



    private void deleteAddedUsers() throws RemoteException, UserAdminUserAdminException {
        UserManagementClient usrMgtClient = new UserManagementClient(getSecondaryISURI(), "admin", "admin");
        usrMgtClient.deleteUser(usrName);
    }

     private Property[] getOIDCAuthnConfigProperties() throws IdentityOAuthAdminException {

        Property[] properties = new Property[7];
        Property property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.IDP_NAME);
        property.setValue("oidcFedIdP");
        properties[0] = property;

        //client id
        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.CLIENT_ID);
        //consumerKeyForPrimaryIS = OAuthUtil.getRandomNumber();
        property.setValue(consumerKeyForPrimaryIS);
        properties[1] = property;

        //client secret
        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.CLIENT_SECRET);
        //consumerSecretForPrimaryIS = OAuthUtil.getRandomNumber();
        property.setValue(consumerSecretForPrimaryIS);
        properties[2] = property;

        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.OAUTH2_AUTHZ_URL);
        property.setValue("https://localhost:9854/oauth2/authorize");
        properties[3] = property;

        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
        property.setValue("https://localhost:9854/oauth2/token");
        properties[4] = property;

        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.CALLBACK_URL);
        //should be updated to the port number of the primary IS
        property.setValue(CALLBACK_URL);
        properties[5] = property;

        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.OIDC_LOGOUT_URL);
        property.setValue("https://localhost:9854/oidc/logout");
        properties[6] = property;
        return properties;
    }

    private void updateServiceProviderWithSAMLConfigs(int portOffset, String issuerName,
                                                      String acsUrl,
                                                      ServiceProvider serviceProvider)
            throws Exception {

        String attributeConsumingServiceIndex = super.createSAML2WebSSOConfiguration(portOffset, getSAMLSSOServiceProviderDTO(issuerName, acsUrl));
        Assert.assertNotNull(attributeConsumingServiceIndex, "Failed to create SAML2 Web SSO configuration for issuer '" + issuerName + "'");

        InboundAuthenticationRequestConfig samlAuthenticationRequestConfig = new InboundAuthenticationRequestConfig();
        samlAuthenticationRequestConfig.setInboundAuthKey(issuerName);
        samlAuthenticationRequestConfig.setInboundAuthType(INBOUND_AUTH_TYPE);
        org.wso2.carbon.identity.application.common.model.xsd.Property property = new org.wso2.carbon.identity.application.common.model.xsd.Property();
        property.setName("attrConsumServiceIndex");
        property.setValue(attributeConsumingServiceIndex);
        samlAuthenticationRequestConfig.setProperties(new org.wso2.carbon.identity.application.common.model.xsd.Property[]{property});

        serviceProvider.getInboundAuthenticationConfig().setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{samlAuthenticationRequestConfig});
    }

    private void updateServiceProviderWithOIDCConfigs(int portOffset, String applicationName,String callbackUrl, ServiceProvider serviceProvider) throws Exception {

        OIDCApplication application = new OIDCApplication(applicationName, OAuth2Constant.TRAVELOCITY_APP_CONTEXT_ROOT, callbackUrl);

        OAuthConsumerAppDTO appDTO = new OAuthConsumerAppDTO();
        appDTO.setApplicationName(application.getApplicationName());
        appDTO.setCallbackUrl(application.getCallBackURL());
        appDTO.setOAuthVersion(OAuth2Constant.OAUTH_VERSION_2);
        appDTO.setGrantTypes("authorization_code implicit password client_credentials refresh_token " +
                "urn:ietf:params:oauth:grant-type:saml2-bearer iwa:ntlm");

//        appDTO.setOauthConsumerKey(OAuthUtil.getRandomNumber());
//        appDTO.setOauthConsumerSecret(OAuthUtil.getRandomNumber());
       // ServiceProvider serviceProvider1 = new ServiceProvider();

        //appMgtclient.createApplication(serviceProvider1);

        //serviceProvider1 = appMgtclient.getApplication(application.getApplicationName());

        //adminClient.registerOAuthApplicationData(appDTO);


        OAuthConsumerAppDTO[] appDtos = createOIDCConfiguration(portOffset, appDTO);

        for (OAuthConsumerAppDTO appDto : appDtos) {
            if (appDto.getApplicationName().equals(application.getApplicationName())) {
                    application.setClientId(appDto.getOauthConsumerKey());
                application.setClientSecret(appDto.getOauthConsumerSecret());
            }
        }

        ClaimConfig claimConfig = null;
        if (!application.getRequiredClaims().isEmpty()) {
            claimConfig = new ClaimConfig();
            for (String claimUri : application.getRequiredClaims()) {
                Claim claim = new Claim();
                claim.setClaimUri(claimUri);
                ClaimMapping claimMapping = new ClaimMapping();
                claimMapping.setRequested(true);
                claimMapping.setLocalClaim(claim);
                claimMapping.setRemoteClaim(claim);
                claimConfig.addClaimMappings(claimMapping);
            }
        }

        //adminClient.updateConsumerApplication(appDTO);

        serviceProvider.setClaimConfig(claimConfig);
        serviceProvider.setOutboundProvisioningConfig(new OutboundProvisioningConfig());
        List<InboundAuthenticationRequestConfig> authRequestList = new ArrayList<>();

        if (application.getClientId() != null) {
            InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig = new InboundAuthenticationRequestConfig();
            inboundAuthenticationRequestConfig.setInboundAuthKey(application.getClientId());
            consumerKeyForPrimaryIS = application.getClientId();
            inboundAuthenticationRequestConfig.setInboundAuthType(OAuth2Constant.OAUTH_2);
            if (StringUtils.isNotBlank(application.getClientSecret())) {
                org.wso2.carbon.identity.application.common.model.xsd.Property property = new org.wso2.carbon.identity.application.common.model.xsd.Property();
                property.setName(OAuth2Constant.OAUTH_CONSUMER_SECRET);
                property.setValue(application.getClientSecret());
                consumerSecretForPrimaryIS = application.getClientSecret();
                org.wso2.carbon.identity.application.common.model.xsd.Property[] properties = {property};
                inboundAuthenticationRequestConfig.setProperties(properties);
            }
            serviceProvider.getInboundAuthenticationConfig().setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{inboundAuthenticationRequestConfig});
            authRequestList.add(inboundAuthenticationRequestConfig);
        }

        super.updateServiceProvider(PORT_OFFSET_1, serviceProvider);

       // appMgtclient.updateApplicationData(serviceProvider1);



//        if (authRequestList.size() > 0) {
//            serviceProvider.getInboundAuthenticationConfig().setInboundAuthenticationRequestConfigs(authRequestList
//                    .toArray(new InboundAuthenticationRequestConfig[authRequestList.size()]));
//        }


//        OAuthConsumerAppDTO appDTO = getOAuthConsumerAppDTO(application);
//
//        appDTO.setOauthConsumerKey(OAuthUtil.getRandomNumber());
//        appDTO.setOauthConsumerSecret(OAuthUtil.getRandomNumber());
//
//       // adminClient.registerOAuthApplicationData(appDTO);
//        //OAuthConsumerAppDTO[] appDtos = adminClient.getAllOAuthApplicationData();
////
////        for (OAuthConsumerAppDTO appDto : appDtos) {
////            if (appDto.getApplicationName().equals(application.getApplicationName())) {
////
////            }
////        }
//
//        application.setClientId(appDTO.getOauthConsumerKey());
//        application.setClientSecret(appDTO.getOauthConsumerSecret());

//        ClaimConfig claimConfig = null;
//        if (!application.getRequiredClaims().isEmpty()) {
//            claimConfig = new ClaimConfig();
//            for (String claimUri : application.getRequiredClaims()) {
//                Claim claim = new Claim();
//                claim.setClaimUri(claimUri);
//                ClaimMapping claimMapping = new ClaimMapping();
//                claimMapping.setRequested(true);
//                claimMapping.setLocalClaim(claim);
//                claimMapping.setRemoteClaim(claim);
//                claimConfig.addClaimMappings(claimMapping);
//            }
//        }

//        serviceProvider.setClaimConfig(claimConfig);
//        serviceProvider.setOutboundProvisioningConfig(new OutboundProvisioningConfig());
       // List<InboundAuthenticationRequestConfig> authRequestList = new ArrayList<>();

//        if (application.getClientId() != null) {
//            InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig = new InboundAuthenticationRequestConfig();
//            inboundAuthenticationRequestConfig.setInboundAuthKey(application.getClientId());
//            consumerKeyForPrimaryIS = application.getClientId();
//            inboundAuthenticationRequestConfig.setInboundAuthType(OAuth2Constant.OAUTH_2);
//            if (StringUtils.isNotBlank(application.getClientSecret())) {
//                org.wso2.carbon.identity.application.common.model.xsd.Property property = new org.wso2.carbon.identity.application.common.model.xsd.Property();
//                property.setName(OAuth2Constant.OAUTH_CONSUMER_SECRET);
//                property.setValue(application.getClientSecret());
//                consumerSecretForPrimaryIS = application.getClientSecret();
//                org.wso2.carbon.identity.application.common.model.xsd.Property[] properties = {property};
//                inboundAuthenticationRequestConfig.setProperties(properties);
//            }
//            serviceProvider.getInboundAuthenticationConfig().setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{inboundAuthenticationRequestConfig});
//           // authRequestList.add(inboundAuthenticationRequestConfig);
//        }

//        if (authRequestList.size() > 0) {
//            serviceProvider.getInboundAuthenticationConfig().setInboundAuthenticationRequestConfigs(authRequestList
//                    .toArray(new InboundAuthenticationRequestConfig[authRequestList.size()]));
//        }

//        ServiceProvider serviceProvider = new ServiceProvider();
//        serviceProvider.setApplicationName(application.getApplicationName());
//        serviceProvider.setDescription(application.getApplicationName());

    }

    private SAMLSSOServiceProviderDTO getSAMLSSOServiceProviderDTO(String issuerName,
                                                                   String acsUrl) {

        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer(issuerName);
        samlssoServiceProviderDTO.setAssertionConsumerUrls(new String[]{acsUrl});
        samlssoServiceProviderDTO.setDefaultAssertionConsumerUrl(acsUrl);
        samlssoServiceProviderDTO.setNameIDFormat(SAML_NAME_ID_FORMAT);
        samlssoServiceProviderDTO.setDoSignAssertions(true);
        samlssoServiceProviderDTO.setDoSignResponse(true);
        samlssoServiceProviderDTO.setDoSingleLogout(true);
        samlssoServiceProviderDTO.setEnableAttributeProfile(true);
        samlssoServiceProviderDTO.setEnableAttributesByDefault(true);
        return samlssoServiceProviderDTO;
    }

    private OAuthConsumerAppDTO getOAuthConsumerAppDTO(OIDCApplication application) throws Exception{
        OAuthConsumerAppDTO appDTO = new OAuthConsumerAppDTO();
        appDTO.setApplicationName(application.getApplicationName());
        appDTO.setCallbackUrl(application.getCallBackURL());
        appDTO.setOAuthVersion(OAuth2Constant.OAUTH_VERSION_2);
        appDTO.setGrantTypes("authorization_code implicit password client_credentials refresh_token " +
                "urn:ietf:params:oauth:grant-type:saml2-bearer iwa:ntlm");

        //adminClient.registerOAuthApplicationData(appDTO);
        return appDTO;
    }
}
