package com.budjb.jaxrs.security

import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException
import javax.servlet.http.HttpServletRequest

abstract class AuthenticationProvider {
    /**
     * Return the name of this provider.
     *
     * @return
     */
    public abstract String getKey()

    /**
     * Returns the name of the client "type" used to identify users along with their principal identity.
     *
     * @return
     */
    public abstract String getClientType()

    /**
     * Attempts to authenticate the user given a request.
     *
     * @param request
     * @return
     */
    public abstract ClientSecurityContext authenticate(HttpServletRequest request) throws UnauthorizedClientException, ForbiddenClientException
}
