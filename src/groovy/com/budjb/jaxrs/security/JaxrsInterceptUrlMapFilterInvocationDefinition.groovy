package com.budjb.jaxrs.security

import java.util.Collection

import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.util.Assert

import grails.plugin.springsecurity.web.access.intercept.InterceptUrlMapFilterInvocationDefinition

class JaxrsInterceptUrlMapFilterInvocationDefinition extends InterceptUrlMapFilterInvocationDefinition {
    /**
     * Returns attributes for a given request, if any exist.
     */
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        Assert.isTrue(object != null && supports(object.getClass()), "Object must be a FilterInvocation")

        FilterInvocation filterInvocation = (FilterInvocation)object

        String url = determineUrl(filterInvocation)

        Collection<ConfigAttribute> configAttributes
        try {
            if (url =~ '^/(jaxrs|jaxrs/.*)$') {
                url = url = filterInvocation.request.forwardURI - filterInvocation.request.contextPath
            }
            configAttributes = findConfigAttributes(url, filterInvocation.getRequest().getMethod())
        }
        catch (RuntimeException e) {
            throw e
        }
        catch (Exception e) {
            throw new RuntimeException(e)
        }

        if ((configAttributes == null || configAttributes.isEmpty()) && rejectIfNoRule) {
            return DENY
        }

        return configAttributes
    }
}
