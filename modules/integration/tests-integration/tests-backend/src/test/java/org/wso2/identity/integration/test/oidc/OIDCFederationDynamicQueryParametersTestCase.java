/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.identity.integration.test.oidc;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.automation.engine.context.AutomationContext;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.identity.application.common.model.idp.xsd.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.idp.xsd.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.idp.xsd.Property;
import org.wso2.carbon.identity.application.common.model.xsd.AuthenticationStep;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminService;

import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceIdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.user.mgt.stub.UserAdminUserAdminException;
import org.wso2.identity.integration.common.clients.Idp.IdentityProviderMgtServiceClient;
import org.wso2.identity.integration.common.clients.UserManagementClient;
import org.wso2.identity.integration.common.clients.application.mgt.ApplicationManagementServiceClient;
import org.wso2.identity.integration.common.clients.oauth.OauthAdminClient;
import org.wso2.identity.integration.common.clients.sso.saml.SAMLSSOConfigServiceClient;
import org.wso2.identity.integration.test.application.mgt.AbstractIdentityFederationTestCase;
import org.wso2.identity.integration.test.base.SecondaryCarbonServerInitializerTestCase;
import org.wso2.identity.integration.test.base.TestDataHolder;
import org.wso2.identity.integration.test.util.Utils;


import org.wso2.identity.integration.test.utils.CommonConstants;
import org.wso2.identity.integration.test.utils.IdentityConstants;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Integration test for Dynamic Query parameter support for OIDC Federated Authenticator.
 */

public class OIDCFederationDynamicQueryParametersTestCase extends AbstractIdentityFederationTestCase {

    private static final String IDENTITY_PROVIDER_NAME = "testIdp";
    public static final String SERVICE_PROVIDER = "SERVICE_PROVIDER";
    public static final String SECONDARY_IS_SERVICE_PROVIDER_NAME = "IS_SP";
    public static final String CALLBACK_URL = "http://localhost.com:8490/travelocity.com/oauth2client";
    public static final String CALLBACK_URL_PRIMARY_IS = "https://localhost:9853/commonauth";
    public static final String INBOUND_AUTH_KEY = "travelocity.com";
    public static final String INBOUND_AUTH_TYPE = "samlsso";
    private static final String OIDCAUTHENTICATOR = "OpenIDConnectAuthenticator";
    private ApplicationManagementServiceClient appMgtclient;
    private ApplicationManagementServiceClient fedAppMgtClient;
    private IdentityProviderMgtServiceClient idpMgtClient;
    private OauthAdminClient oauthAdminClient;
    private SAMLSSOConfigServiceClient ssoConfigServiceClient;
    private OAuthAdminServiceImpl oAuthAdminService =  new OAuthAdminServiceImpl();

//
//    private String consumerSecretForPrimaryIS = "secret";
//    private String consumerKeyForPrimaryIS = "key";

//    {
//        try {
//            consumerSecretForPrimaryIS = OAuthUtil.getRandomNumber();
//            consumerKeyForPrimaryIS = OAuthUtil.getRandomNumber();
//        } catch (IdentityOAuthAdminException e) {
//            e.printStackTrace();
//        }
//    }

    protected static final int PORT_OFFSET_0 = 0;
    private static final int PORT_OFFSET_1 = 1;

    private String usrName = "testFederatedUser";
    private String usrPwd = "testFederatePassword";
    private String usrRole = "admin";


    private static final String INBOUND_QUERY_PARAM = "inbound_request_param_key";
    private static final String INBOUND_QUERY_PARAM_VALUE = "inbound_request_param_value";

    private static final String DYNAMIC_QUERY_PARAM_KEY = "dynamic_query";
    private static final String DYNAMIC_QUERY = "dynamic_query={inbound_request_param_key}";


    private static final String FEDERATED_AUTHENTICATION_TYPE = "federated";
    private static final String TRAVELOCITY_SAMPLE_APP_URL = "http://localhost:8490/travelocity.com";

    @BeforeClass(alwaysRun = true)
    public void initTest() throws Exception {

        super.initTest();

        String userName = userInfo.getUserName();
        String password = userInfo.getPassword();

        appMgtclient = new ApplicationManagementServiceClient(sessionCookie, backendURL, null);
        fedAppMgtClient = new ApplicationManagementServiceClient(sessionCookie, backendURL, null);
        idpMgtClient = new IdentityProviderMgtServiceClient(userName, password, backendURL);
        oauthAdminClient = new OauthAdminClient(backendURL, sessionCookie);
        ssoConfigServiceClient = new SAMLSSOConfigServiceClient(backendURL, userName, password);

//        //Start the federated Identity Server.
//        Map<String, String> startupParameters = new HashMap<String, String>();
//        startupParameters.put("-DportOffset", String.valueOf(PORT_OFFSET_1 + CommonConstants.IS_DEFAULT_OFFSET));
//        AutomationContext context = new AutomationContext("IDENTITY", "identity002", TestUserMode.SUPER_TENANT_ADMIN);
//
//        startCarbonServer(PORT_OFFSET_1, context, startupParameters);
//
//        super.createServiceClients(PORT_OFFSET_0, sessionCookie, new IdentityConstants
//                .ServiceClientType[]{IdentityConstants.ServiceClientType.APPLICATION_MANAGEMENT, IdentityConstants.ServiceClientType.IDENTITY_PROVIDER_MGT, IdentityConstants.ServiceClientType.SAML_SSO_CONFIG});
//        super.createServiceClients(PORT_OFFSET_1, null, new IdentityConstants.ServiceClientType[]{IdentityConstants.ServiceClientType.APPLICATION_MANAGEMENT, IdentityConstants.ServiceClientType.SAML_SSO_CONFIG});
//        //add new test user to secondary IS
//        boolean userCreated = addUserToSecondaryIS();
//        Assert.assertTrue(userCreated, "User creation failed");
//
//        //add Primary IS as a service provider to the secondary IS.
//        addServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);
//
//        //configure the Primary IS service provider.
//        ServiceProvider primaryIS = getServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);
//        updateServiceProviderWithOIDCConfigs(primaryIS);
//
//        updateServiceProvider(PORT_OFFSET_1, primaryIS);
//
//        primaryIS = getServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);
//
//        InboundAuthenticationRequestConfig[] configs = primaryIS.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
//        boolean success = false;
//        if (configs != null) {
//            for (InboundAuthenticationRequestConfig config : configs) {
//                if (config.getInboundAuthType().equals("openidconnect")) {
//                    success = true;
//                    break;
//
//                }
//            }
//        }
//
//        Assert.assertTrue(success, "Failed to update service provider with inbound SAML2 configs in secondary IS");

    }

    @AfterClass(alwaysRun = true)
    public void endTest() throws Exception {

        appMgtclient.deleteApplication(SERVICE_PROVIDER);
        idpMgtClient.deleteIdP(IDENTITY_PROVIDER_NAME);

        appMgtclient = null;
        idpMgtClient = null;

       // deleteServiceProvider(PORT_OFFSET_1, SECONDARY_IS_SERVICE_PROVIDER_NAME);

//        //delete added users to secondary IS
//        deleteAddedUsers();

        super.stopCarbonServer(PORT_OFFSET_1);
    }

    @Test(groups = "wso2.is", description = "Test federated IDP creation with OIDC Federated Authenticator")
    public void testIdpWithDynamicQueryParams() throws Exception {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setIdentityProviderName(IDENTITY_PROVIDER_NAME);

        FederatedAuthenticatorConfig oidcAuthnConfig = new FederatedAuthenticatorConfig();
        oidcAuthnConfig.setName(OIDCAUTHENTICATOR);
        oidcAuthnConfig.setDisplayName("openidconnect");
        oidcAuthnConfig.setEnabled(true);
        oidcAuthnConfig.setProperties(getOIDCAuthnConfigProperties());
        identityProvider.setDefaultAuthenticatorConfig(oidcAuthnConfig);
        identityProvider.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{oidcAuthnConfig});

        idpMgtClient.addIdP(identityProvider);

        IdentityProvider idPByName = idpMgtClient.getIdPByName(IDENTITY_PROVIDER_NAME);
        Assert.assertNotNull(idPByName);
    }

//    @Test(groups = "wso2.is", description = "Test Service Provider creation with SAML Federated IDP Authentication",
//            dependsOnMethods = {"testIdpWithDynamicQueryParams"})
//    public void testCreateServiceProviderWithOIDCConfigsAndOIDCFedIdp() throws Exception {
//
//        ServiceProvider serviceProvider = new ServiceProvider();
//        serviceProvider.setApplicationName(SERVICE_PROVIDER);
//        appMgtclient.createApplication(serviceProvider);
//
//        serviceProvider = appMgtclient.getApplication(SERVICE_PROVIDER);
//        Assert.assertNotNull(serviceProvider, "Service Provider creation has failed.");
//
//        // Set OAuth/OIDC Inbound for the service provider.
//       //ssoConfigServiceClient.addServiceProvider(createConsumerAppDTOForTravelocityApp()));
//        OAuthConsumerAppDTO dto = createConsumerAppDTOForPickupDispatchApp();
//        oauthAdminClient.registerOAuthApplicationData(dto);
//        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
//        InboundAuthenticationRequestConfig requestConfig = new InboundAuthenticationRequestConfig();
//        requestConfig.setInboundAuthKey(INBOUND_AUTH_KEY);
//        requestConfig.setInboundAuthType(INBOUND_AUTH_TYPE);
//
//        org.wso2.carbon.identity.application.common.model.xsd.Property attributeConsumerServiceIndexProp =
//                new org.wso2.carbon.identity.application.common.model.xsd.Property();
//        attributeConsumerServiceIndexProp.setName("attrConsumServiceIndex");
//        attributeConsumerServiceIndexProp.setValue("1239245949");
//        requestConfig.setProperties(new org.wso2.carbon.identity.application.common.model.xsd.Property[]{
//                attributeConsumerServiceIndexProp});
//        inboundAuthenticationConfig
//                .setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{requestConfig});
//        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
//
//         // Add OIDC IDP as authentication step.
//        AuthenticationStep authStep = new AuthenticationStep();
//        org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider idP =
//                new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider();
//        idP.setIdentityProviderName(IDENTITY_PROVIDER_NAME);
//        org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig oidcAuthnConfig = new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig();
//        oidcAuthnConfig.setName("OIDCAuthenticator");
//        oidcAuthnConfig.setDisplayName("openidconnect");
//        idP.setFederatedAuthenticatorConfigs(new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig[]{oidcAuthnConfig});
//        authStep.setFederatedIdentityProviders(
//                new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider[]{idP});
//        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationSteps(
//                new AuthenticationStep[]{authStep});
//        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationType(FEDERATED_AUTHENTICATION_TYPE);
//
//        appMgtclient.updateApplicationData(serviceProvider);
//        //serviceProvider = appMgtclient.getApplication(SERVICE_PROVIDER);
//
//        Assert.assertNotNull(serviceProvider);
//
//        Assert.assertNotNull(serviceProvider.getInboundAuthenticationConfig());
//        InboundAuthenticationRequestConfig[] inboundAuthenticationRequestConfigs =
//                serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
//        Assert.assertNotNull(inboundAuthenticationRequestConfigs);
//
//        boolean inboundAuthUpdateSuccess = false;
//        for (InboundAuthenticationRequestConfig config : inboundAuthenticationRequestConfigs) {
//            if (INBOUND_AUTH_KEY.equals(config.getInboundAuthKey())
//                    && INBOUND_AUTH_TYPE.equals(config.getInboundAuthType())) {
//                inboundAuthUpdateSuccess = true;
//                break;
//            }
//        }
//        Assert.assertTrue(inboundAuthUpdateSuccess, "Failed to update service provider with OIDC inbound configs.");
//
//        Assert.assertNotNull(serviceProvider.getLocalAndOutBoundAuthenticationConfig());
//        Assert.assertEquals(serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationType(),
//                FEDERATED_AUTHENTICATION_TYPE);
//
//    }

    @Test(groups = "wso2.is", description = "Test Service Provider creation with SAML Federated IDP Authentication",
            dependsOnMethods = {"testIdpWithDynamicQueryParams"})
    public void testCreateServiceProviderWithSAMLConfigsAndOIDCFedIdp() throws Exception {

//        ServiceProvider serviceProvider = new ServiceProvider();
//        serviceProvider.setApplicationName(PRIMARYIS_SP);
//        appMgtclient.createApplication(serviceProvider);
//
//        serviceProvider = appMgtclient.getApplication(PRIMARYIS_SP);
//        Assert.assertNotNull(serviceProvider, "Primary IS SP creation has failed.");

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(SERVICE_PROVIDER);
        appMgtclient.createApplication(serviceProvider);

        serviceProvider = appMgtclient.getApplication(SERVICE_PROVIDER);
        Assert.assertNotNull(serviceProvider, "Service Provider creation has failed.");



       // Set SAML Inbound for the service provider.
        ssoConfigServiceClient.addServiceProvider(createSsoServiceProviderDTOForTravelocityApp());
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        InboundAuthenticationRequestConfig requestConfig = new InboundAuthenticationRequestConfig();
        requestConfig.setInboundAuthKey(INBOUND_AUTH_KEY);
        requestConfig.setInboundAuthType(INBOUND_AUTH_TYPE);

        org.wso2.carbon.identity.application.common.model.xsd.Property attributeConsumerServiceIndexProp =
                new org.wso2.carbon.identity.application.common.model.xsd.Property();
        attributeConsumerServiceIndexProp.setName("attrConsumServiceIndex");
        attributeConsumerServiceIndexProp.setValue("1239245949");
        requestConfig.setProperties(new org.wso2.carbon.identity.application.common.model.xsd.Property[]{
                attributeConsumerServiceIndexProp});
        inboundAuthenticationConfig
                .setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{requestConfig});
        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);


//        // Add OIDC IDP as authentication step.
//        AuthenticationStep authStep = new AuthenticationStep();
//        org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider idP =
//                new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider();
//        idP.setIdentityProviderName(IDENTITY_PROVIDER_NAME);
//        FederatedAuthenticatorConfig oidcAuthnConfig = idpMgtClient.getIdPByName(IDENTITY_PROVIDER_NAME).getFederatedAuthenticatorConfigs()[0];
//        Assert.assertNotNull(oidcAuthnConfig);
//        authStep.setFederatedIdentityProviders(
//                new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider[]{idP});
//        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationSteps(
//                new AuthenticationStep[]{authStep});
//        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationType(FEDERATED_AUTHENTICATION_TYPE);

         // Add SAML IDP as authentication step.
        AuthenticationStep authStep = new AuthenticationStep();
        org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider idP =
                new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider();
        idP.setIdentityProviderName(IDENTITY_PROVIDER_NAME);
        org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig saml2SSOAuthnConfig = new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig();
        saml2SSOAuthnConfig.setName(OIDCAUTHENTICATOR);
        saml2SSOAuthnConfig.setDisplayName("openidconnect");
        idP.setFederatedAuthenticatorConfigs(new org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig[]{saml2SSOAuthnConfig});
        authStep.setFederatedIdentityProviders(
                new org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider[]{idP});
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationSteps(
                new AuthenticationStep[]{authStep});
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationType(FEDERATED_AUTHENTICATION_TYPE);

        appMgtclient.updateApplicationData(serviceProvider);
        serviceProvider = appMgtclient.getApplication(SERVICE_PROVIDER);

        Assert.assertNotNull(serviceProvider);

        Assert.assertNotNull(serviceProvider.getInboundAuthenticationConfig());
        InboundAuthenticationRequestConfig[] inboundAuthenticationRequestConfigs =
                serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs();
        Assert.assertNotNull(inboundAuthenticationRequestConfigs);

        boolean inboundAuthUpdateSuccess = false;
        for (InboundAuthenticationRequestConfig config : inboundAuthenticationRequestConfigs) {
            if (INBOUND_AUTH_KEY.equals(config.getInboundAuthKey())
                    && INBOUND_AUTH_TYPE.equals(config.getInboundAuthType())) {
                inboundAuthUpdateSuccess = true;
                break;
            }
        }
        Assert.assertTrue(inboundAuthUpdateSuccess, "Failed to update service provider with SAML inbound configs.");

        Assert.assertNotNull(serviceProvider.getLocalAndOutBoundAuthenticationConfig());
        Assert.assertEquals(serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationType(),
                FEDERATED_AUTHENTICATION_TYPE);
    }

    @Test(alwaysRun = true, description = "Test SAML Federation Request with Dynamic Query Parameters",
            dependsOnMethods = {"testCreateServiceProviderWithSAMLConfigsAndSAMLFedIdp"})
    public void testOIDCRedirectBindingDynamicWithInboundQueryParam() throws Exception {

        HttpGet request = new HttpGet(TRAVELOCITY_SAMPLE_APP_URL + "/samlsso?SAML2.HTTPBinding=HTTP-Redirect");
        CloseableHttpClient client = null;
        try {
            client = HttpClientBuilder.create().disableRedirectHandling().build();
            // Do a redirect to travelocity app.
            HttpResponse response = client.execute(request);
            EntityUtils.consume(response.getEntity());

            // Modify the location header to included the secToken.
            String location = Utils.getRedirectUrl(response) + "&" + INBOUND_QUERY_PARAM + "=" + INBOUND_QUERY_PARAM_VALUE;

            // Do a GET manually to send the SAML Request to IS.
            HttpGet requestToIS = new HttpGet(location);
            HttpResponse requestToFederatedIdp = client.execute(requestToIS);
            EntityUtils.consume(requestToFederatedIdp.getEntity());

            // 302 to SAML Federated IDP initiated from the primary IS
            String requestToFedIdpLocationHeader = Utils.getRedirectUrl(requestToFederatedIdp);
            // Assert whether the query param value sent in the inbound request was passed in the 302 to Federated IDP
            List<NameValuePair> nameValuePairs = buildQueryParamList(requestToFedIdpLocationHeader);
            boolean isDynamicQueryParamReplaced = false;
            for (NameValuePair valuePair : nameValuePairs) {
                if (StringUtils.equalsIgnoreCase(DYNAMIC_QUERY_PARAM_KEY, valuePair.getName())) {
                    // Check whether the query param value sent in inbound request was included to the additional query
                    // params defined in the SAML Application Authenticator.
                    isDynamicQueryParamReplaced = StringUtils.equals(valuePair.getValue(), INBOUND_QUERY_PARAM_VALUE);
                }
            }
            Assert.assertTrue(isDynamicQueryParamReplaced);
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    private List<NameValuePair> buildQueryParamList(String requestToFedIdpLocationHeader) {

        return URLEncodedUtils.parse(requestToFedIdpLocationHeader, StandardCharsets.UTF_8);
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
        String consumerKeyForPrimaryIS = OAuthUtil.getRandomNumber();
        property.setValue(consumerKeyForPrimaryIS);
        properties[1] = property;

        //client secret
        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.CLIENT_SECRET);
        String consumerSecretForPrimaryIS = OAuthUtil.getRandomNumber();
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
        property.setValue("https://localhost:9854/commonauth");
        properties[5] = property;

        property = new Property();
        property.setName(IdentityConstants.Authenticator.OIDC.OIDC_LOGOUT_URL);
        property.setValue("https://localhost:9854/oidc/logout");
        properties[6] = property;
        return properties;
    }



    private OAuthConsumerAppDTO createConsumerAppDTOForPrimaryIS() throws OAuthAdminServiceIdentityOAuthAdminException, RemoteException, IdentityOAuthAdminException {
        OAuthConsumerAppDTO app = new OAuthConsumerAppDTO();
        app.setCallbackUrl(CALLBACK_URL_PRIMARY_IS);
        app.setOAuthVersion("OAuth-2.0");
        app.setGrantTypes("refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password client_" +
                "credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:uma-ticket urn:ietf:params:" +
                "oauth:grant-type:jwt-bearer ");
        app.setRenewRefreshTokenEnabled("true");
        app.setTokenType("Default");
//        app.setOauthConsumerKey(OAuthUtil.getRandomNumber());
//        app.setOauthConsumerSecret(OAuthUtil.getRandomNumber());

//        OAuthAppDO appDO = new OAuthAppDO();
//        appDO.setApplicationName("pickup-dispatch");
//        appDO.setCallbackUrl(CALLBACK_URL);
//        appDO.setOauthVersion("OAuth-2.0");
//        appDO.setGrantTypes("refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password client_" +
//                "credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:uma-ticket urn:ietf:params:" +
//                "oauth:grant-type:jwt-bearer ");
//        appDO.setRenewRefreshTokenEnabled("true");
//        appDO.setTokenType("Default");

        return app;

        //return oAuthAdminService.registerAndRetrieveOAuthApplicationData(app);
    }

    private SAMLSSOServiceProviderDTO createSsoServiceProviderDTOForTravelocityApp() {

        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer(INBOUND_AUTH_KEY);
        samlssoServiceProviderDTO.setAssertionConsumerUrls(new String[]{TRAVELOCITY_SAMPLE_APP_URL + "/home" +
                ".jsp"});
        samlssoServiceProviderDTO.setDefaultAssertionConsumerUrl(TRAVELOCITY_SAMPLE_APP_URL + "/home.jsp");
        samlssoServiceProviderDTO.setAttributeConsumingServiceIndex("1239245949");
        samlssoServiceProviderDTO.setNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        samlssoServiceProviderDTO.setDoSignAssertions(true);
        samlssoServiceProviderDTO.setDoSignResponse(true);
        samlssoServiceProviderDTO.setDoSingleLogout(true);
        samlssoServiceProviderDTO.setLoginPageURL("/carbon/admin/login.jsp");
        return samlssoServiceProviderDTO;
    }

    private void updateServiceProviderWithOIDCConfigs(ServiceProvider serviceProvider) throws Exception{


        InboundAuthenticationRequestConfig oidcAuthenticationRequestConfig = new InboundAuthenticationRequestConfig();
        oidcAuthenticationRequestConfig.setInboundAuthType("openidconnect");
        org.wso2.carbon.identity.application.common.model.xsd.Property[] properties = new org.wso2.carbon.identity.application.common.model.xsd.Property[3];

        org.wso2.carbon.identity.application.common.model.xsd.Property property = new org.wso2.carbon.identity.application.common.model.xsd.Property();
        property.setName(IdentityConstants.Authenticator.OIDC.CALLBACK_URL);
        property.setValue(CALLBACK_URL_PRIMARY_IS);
        properties[0] = property;

//        property = new org.wso2.carbon.identity.application.common.model.xsd.Property();
//        property.setName(IdentityConstants.Authenticator.OIDC.CLIENT_ID);
//        property.setValue(consumerKeyForPrimaryIS);
//        properties[1] = property;
//
//        property = new org.wso2.carbon.identity.application.common.model.xsd.Property();
//        property.setName(IdentityConstants.Authenticator.OIDC.CLIENT_SECRET);
//        property.setValue(consumerSecretForPrimaryIS);
//        properties[2] = property;

        oidcAuthenticationRequestConfig.setProperties(properties);

        serviceProvider.getInboundAuthenticationConfig().setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{oidcAuthenticationRequestConfig});
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

    protected String getSecondaryISURI() {
        return String.format("https://localhost:%s/services/", DEFAULT_PORT + PORT_OFFSET_1);
    }

    private void deleteAddedUsers() throws RemoteException, UserAdminUserAdminException {
        UserManagementClient usrMgtClient = new UserManagementClient(getSecondaryISURI(), "admin", "admin");
        usrMgtClient.deleteUser(usrName);
    }


}
