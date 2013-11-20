package com.budjb.jaxrs.security

public class ClientSecurityContext {
    /**
     * Name assigned to anonymous clients.
     */
    private static final String ANONYMOUS_KEY = '__anonymous__'

    /**
     * An instance of an anonymous client.
     */
    public static final ClientSecurityContext ANONYMOUS = new ClientSecurityContext(ANONYMOUS_KEY)

    /**
     * API key associated with the client.
     */
    public String apiKey

    /**
     * Whether the
     */
    public boolean getIsAnonymous() {
        return apiKey == ANONYMOUS_KEY
    }

    /**
     * Constructor.
     *
     * @param apiKey
     */
    public ClientSecurityContext(String apiKey) {
        this.apiKey = apiKey
    }

    /**
     * Return the client instance for the api key.
     *
     * @return Client instance associated with the api key, or null if anonymous.
     */
    public JaxrsClient getClient() {
        if (getIsAnonymous()) {
            return null
        }

        return JaxrsClient.find { apiKey == this.apiKey }
    }
}
