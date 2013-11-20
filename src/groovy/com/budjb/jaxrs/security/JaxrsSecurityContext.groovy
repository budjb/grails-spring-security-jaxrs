package com.budjb.jaxrs.security

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
import org.codehaus.groovy.grails.commons.spring.GrailsApplicationContext
import org.grails.jaxrs.DefaultGrailsResourceClass
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.util.Assert

import com.budjb.jaxrs.security.annotation.Requires
import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException

class JaxrsSecurityContext implements InitializingBean {
    /**
     * List of security contexts.
     */
    List<ResourceSecurityContext> securityContexts = []

    /**
     * Holder for the currently logged in user.
     */
    private static ThreadLocal authenticationHolder = new ThreadLocal<ClientSecurityContext>()

    /**
     * Application context.
     */
    @Autowired
    GrailsApplicationContext applicationContext

    /**
     * Grails application.
     */
    GrailsApplication grailsApplication

    /**
     * Logger
     */
    Logger log = Logger.getLogger(getClass())

    /**
     * Api Key header name.
     */
    String apiKeyHeader

    /**
     * Api Key query param.
     */
    String apiKeyQuery

    /**
     * Domain containing api key instances.
     */
    String apiKeyDomain

    /**
     * Default set of allowed auth methods.
     */
    List auth

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
    }

    /**
     * Do some post-injection validation.
     */
    public void afterPropertiesSet() throws Exception {
        // Validate injected beans
        Assert.notNull(grailsApplication)

        // Load the configuration
        loadConfig()

        // Validate configuration options
        // TODO
    }

    /**
     * Load custom configuration.
     */
    protected void loadConfig() {
        // Get the base config
        Class configObject = this.class.classLoader.loadClass('DefaultJaxrsSecurityConfig')

        // Parse the config
        ConfigObject config = new ConfigSlurper(grails.util.Environment.current.name).parse(configObject).clone()

        // Get the config key
        ConfigObject userConfig = grailsApplication.config.grails?.plugin?.jaxrs?.security
        if (userConfig) {
            config.merge(userConfig)
        }

        // Load config options from the config
        apiKeyHeader = config.apiKey?.header
        apiKeyQuery  = config.apiKey?.query
        apiKeyDomain = config.apiKey?.domain
        rejectIfNoRule = config.rejectIfNoRule
        enabled = config.enabled

        // Load the default auth types
        if (config.authTypes instanceof List) {
            auth = config.authTypes.collect { AuthType.valueOf(it) }
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
        // Track the enabled auth types
        List authTypes

        // Check if the context has an authentication configuration defined
        if (context.authTypes) {
            authTypes = context.authTypes.collect { AuthType.valueOf(it) }
        }
        else {
            authTypes = auth
        }

        // If no auth types were given, fail authentication
        if (!authTypes) {
            if (context.noAuth || !rejectIfNoRule) {
                setAnonymousLogin()
                return
            }
            throw new ForbiddenClientException("No authentication methods were configured for this resource.")
        }

        // Attempt authentication
        for (AuthType authType : authTypes) {
            // Get the api key
            String apiKey = getApiKey(request, authType)
            if (!apiKey) {
                continue
            }

            // Find the matching api key in the db
            JaxrsClient jaxrsClient = JaxrsClient.findByApiKey(apiKey)
            if (!jaxrsClient) {
                continue
            }

            // Check for deactivated keys
            if (jaxrsClient.active == false) {
                // If the context allows no auth, set the anonymous user
                if (context.noAuth) {
                    setAnonymousLogin()
                    return
                }

                // Reject the request
                throw new ForbiddenClientException("API key is disabled.")
            }

            // Store a security context for the login
            setClientLogin(apiKey)
            return
        }

        // Fail if noAuth isn't set
        if (!context.noAuth) {
            throw new UnauthorizedClientException("API key was not provided or invalid.")
        }

        // Store an anonymous user
        setAnonymousLogin()
    }

    /**
     * Retrieves an api key from the request.
     *
     * @param request
     * @param context
     * @return
     */
    protected String getApiKey(HttpServletRequest request, AuthType authType) {
        switch (authType) {
            case AuthType.HEADER:
                return request.getHeader(apiKeyHeader)

            case AuthType.QUERY:
                return request.getParameter(apiKeyQuery)
        }

        return null
    }

    /**
     * Sets the authentication for the individual request.
     *
     * @param apiKey
     */
    public void setAuthentication(ClientSecurityContext apiKey) {
        authenticationHolder.set(apiKey)
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
    protected void setAnonymousLogin() {
        authenticationHolder.set(ClientSecurityContext.ANONYMOUS)
    }

    /**
     * Stores a client security context in the authentication holder for the given api key.
     *
     * @param apiKey
     */
    protected void setClientLogin(String apiKey) {
        authenticationHolder.set(new ClientSecurityContext(apiKey))
    }

    protected void authorize(HttpServletRequest request, ResourceSecurityContext context) {
        // Skip checks if noAuth is set on the context
        if (context.noAuth) {
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
}
