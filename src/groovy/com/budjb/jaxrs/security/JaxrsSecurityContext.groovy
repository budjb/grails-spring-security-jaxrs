/*
 * Copyright 2014 Bud Byrd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.budjb.jaxrs.security

import grails.util.Environment
import java.lang.reflect.Method

import javax.servlet.http.HttpServletRequest
import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.HEAD
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path

import org.apache.log4j.Logger
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.grails.jaxrs.DefaultGrailsResourceClass
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.util.Assert

import com.budjb.jaxrs.security.annotation.RequiresRoles
import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException
import com.budjb.jaxrs.security.provider.HeaderApiKeyAuthenticationProvider
import com.budjb.jaxrs.security.provider.QueryApiKeyAuthenticationProvider

class JaxrsSecurityContext implements InitializingBean {
    /**
     * List of security contexts.
     */
    List<ResourceSecurityContext> securityContexts = []

    /**
     * Holder for the currently logged in user.
     */
    private static ThreadLocal<ClientSecurityContext> authenticationHolder = new ThreadLocal<ClientSecurityContext>()

    /**
     * Grails application.
     */
    GrailsApplication grailsApplication

    /**
     * Logger
     */
    Logger log = Logger.getLogger(getClass())

    /**
     * Default set of allowed auth methods.
     */
    List<String> defaultAuthProviders

    /**
     * Authentication broker.
     */
    AuthBroker authBroker

    /**
     * Whether to reject a request if no explicit rule has been set.
     */
    boolean rejectIfNoRule

    /**
     * Whether jaxrs security is enabled.
     */
    boolean enabled

    /**
     * Initializes security contexts.
     */
    public void initialize() {
        // Reset the context
        reset()

        // Load the configuration
        loadConfig()

        // Configure each resource
        grailsApplication.resourceClasses.each { DefaultGrailsResourceClass clazz ->
            initialize(clazz)
        }
    }

    /**
     * Resets the security context.
     */
    public void reset() {
        securityContexts = []
        authBroker = new AuthBroker()
    }

    /**
     * Do some post-injection validation.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(grailsApplication)
    }

    /**
     * Load custom configuration.
     */
    protected void loadConfig() {
        // Get a class loader
        GroovyClassLoader classLoader = new GroovyClassLoader(JaxrsSecurityContext.classLoader)

        // Get the base config
        ConfigObject config
        try {
            ConfigSlurper slurper = new ConfigSlurper(Environment.current.name)
            config = slurper.parse(classLoader.loadClass('DefaultJaxrsSecurityConfig'))
            config = config.security.clone()
        }
        catch (ClassNotFoundException e) {
            log.error("default configuration not found on the classpath", e)
            return
        }

        // Get the config key
        ConfigObject userConfig = grailsApplication.config.jaxrs.security
        if (userConfig) {
            config.merge(userConfig)
        }

        // Load config options from the config
        rejectIfNoRule = config.rejectIfNoRule
        enabled = config.enabled

        // Load the default auth types
        if (config.authProviders instanceof List) {
            defaultAuthProviders = config.authProviders
        }
        else {
            log.warn("jaxrs security configuration value \"authProviders\" must be a list")
        }
    }

    /**
     * Initializes a resource.
     *
     * @param clazz
     */
    protected void initialize(DefaultGrailsResourceClass clazz) {
        securityContexts += ResourceSecurityContext.build(clazz)
    }

    /**
     * Returns the annotation class for the string representation of an HTTP method.
     *
     * @param method
     * @return
     */
    protected Class getHttpMethod(String method) {
        switch (method) {
            case 'GET':
                return GET

            case 'POST':
                return POST

            case 'PUT':
                return PUT

            case 'DELETE':
                return DELETE

            case 'HEAD':
                return HEAD
        }

        throw new IllegalStateException("unable to process ${method} requests")
    }

    /**
     * Processes a request.
     *
     * @param path
     * @param httpMethod
     */
    public void process(HttpServletRequest request) {
        // Short-circuit if the filter is not enabled
        if (!enabled) {
            return
        }

        // Find a matching security context
        ResourceSecurityContext securityContext = findSecurityContext(request.forwardURI - request.contextPath, request.method)

        // No security context was found, which probably means this is a 404
        if (!securityContext) {
            return
        }

        // Authenticate the client
        authenticate(request, securityContext)

        // Authorize the request
        authorize(request, securityContext)
    }

    /**
     * Find a security context for a given HTTP path and method.
     *
     * @param path
     * @param httpMethod
     * @return
     */
    protected ResourceSecurityContext findSecurityContext(String path, String httpMethod) {
        // Get the http method annotation
        Class method = getHttpMethod(httpMethod)

        // Find a matching security context based on absolute match first
        ResourceSecurityContext securityContext = securityContexts.find { it.isAbsolute && it.method == method && it.match(path) }

        // If one wasn't found, find based on regex match
        if (!securityContext) {
            securityContext = securityContexts.find { !it.isAbsolute && it.method == method && it.match(path) }
        }

        return securityContext
    }

    /**
     * Authenticates a request.
     *
     * @param request
     * @param context
     */
    protected void authenticate(HttpServletRequest request, ResourceSecurityContext context) {
        // Get a list of valid providers for the resource
        List<String> providers = context.authProviders ?: defaultAuthProviders ?: []

        // If no auth types were given, fail authentication
        if (!providers) {
            if (context.allowAnonymous) {
                loginAnonymous()
                return
            }
            throw new ForbiddenClientException("No authentication methods were configured for this resource.")
        }

        // Attempt authentication
        ClientSecurityContext clientContext = authBroker.authenticate(request, providers)

        // Check for failed login
        if (!clientContext) {
            // If anonymous login is set, set the anonymous user and continue
            if (context.allowAnonymous) {
                loginAnonymous()
                return
            }

            // Decline the request
            throw new UnauthorizedClientException("Authentication credentials are either missing or invalid.")
        }

        // Check for disabled login
        if (clientContext.getClient().active == false) {
            throw new ForbiddenClientException("Client account has been disabled.")
        }

        // Store a security context for the login
        loginClient(clientContext)
    }

    /**
     * Returns the authentication for the individual request.
     *
     * @return
     */
    public ClientSecurityContext getAuthentication() {
        return authenticationHolder.get()
    }

    /**
     * Stores an anonymous user in the authentication holder.
     */
    protected void loginAnonymous() {
        authenticationHolder.set(ClientSecurityContext.ANONYMOUS)
    }

    /**
     * Stores a client security context in the authentication holder for the given api key.
     *
     * @param apiKey
     */
    protected void loginClient(ClientSecurityContext context) {
        authenticationHolder.set(context)
    }

    /**
     * Authorizes the authenticated user against the requested resource.
     *
     * @param request
     * @param context
     */
    protected void authorize(HttpServletRequest request, ResourceSecurityContext context) {
        // Skip checks if allowAnonymous is set on the context
        if (context.allowAnonymous) {
            return
        }

        // Get the logged in client
        ClientSecurityContext clientContext = getAuthentication()

        // Ensure the client is logged in
        Assert.notNull(clientContext, "client is not logged in")

        // Check if no roles are specified for the context
        if (!context.roles.size()) {
            // Reject the request if configured to do so
            if (rejectIfNoRule) {
                throw new ForbiddenClientException("Access denied due to no security on this API resource.")
            }
            return
        }

        // Reject now if the client is anonymous
        if (clientContext.isAnonymous) {
            throw new ForbiddenClientException("Access denied to anonymous clients.")
        }

        // Load the api key instance
        JaxrsClient client = clientContext.getClient()

        // Check each role
        for (String roleName : context.roles) {
            // Load the role
            JaxrsRole role = JaxrsRole.find { name == roleName }

            // If the role doesn't exist, skip it
            if (!role) {
                log.warn("specified role \"${roleName}\" does not exist")
                continue
            }

            // If an API key/role tuple is found, the request is authorized
            if (JaxrsClientRole.get(client.id, role.id)) {
                return
            }
        }

        throw new ForbiddenClientException("Access denied because client does not have the required role memberships.")
    }

    /**
     * Registers an authentication provider.
     *
     * @param provider
     */
    public void registerAuthenticationProvider(AuthenticationProvider provider) {
        log.debug("registering authentication provider ${provider.class}")
        authBroker.registerAuthenticationProvider(provider)
    }

    /**
     * Returns the client security context for the caller's thread, or null if one is not set.
     *
     * @return
     */
    public ClientSecurityContext getClientSecurityContext() {
        authenticationHolder.get()
    }

    /**
     * Returns the logged in user object, if a user is logged in.
     *
     * Note that anonymous users will always return null.
     *
     * @return
     */
    public JaxrsClient getLoggedInUser() {
        return authenticationHolder.get()?.getClient()
    }
}
