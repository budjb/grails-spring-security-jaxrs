package com.budjb.jaxrs.security

import grails.plugin.springsecurity.web.access.intercept.AbstractFilterInvocationDefinition
import org.codehaus.groovy.grails.commons.GrailsClass
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.FilterInvocation
import org.springframework.util.Assert

import javax.ws.rs.Path

class JaxrsFilterInvocationDefinition extends AbstractFilterInvocationDefinition {
    /**
     * Anonymous permission.
     */
    protected static final Collection<ConfigAttribute> ANONYMOUS
    static {
        Collection<ConfigAttribute> list = new ArrayList<ConfigAttribute>(1)
        list.add(new SecurityConfig("IS_AUTHENTICATED_ANONYMOUSLY"))
        ANONYMOUS = Collections.unmodifiableCollection(list)
    }

    /**
     * List of all known path patterns in all JaxRS resources.
     */
    protected List<String> patterns

    /**
     * Whether to allow an HTTP 404 if a resource does not exist.
     */
    boolean allow404

    /**
     * Initializes the object definition source.
     *
     * @param resourceClasses
     */
    void initialize(GrailsClass[] resourceClasses) {
        resetConfigs()

        resourceClasses.each {
            initializeResource(it)
        }
    }

    /**
     * Initializes a JaxRS resource.
     *
     * @param clazz
     */
    protected void initializeResource(GrailsClass clazz) {
        Class<?> resource = clazz.clazz

        String classPath = resource.getAnnotation(Path)?.value() ?: ''

        resource.declaredMethods.each { method ->
            patterns << buildPattern(classPath, method.getAnnotation(Path)?.value() ?: '')
        }
    }

    /**
     * Replace multiple slashes with one slash, and template path pieces with a .* regex.
     *
     * @param path
     * @return
     */
    protected String buildPattern(String base, String resource) {
        return "${base ?: ''}/${resource ?: ''}".replaceAll(/\/+/, '/').replaceAll(/\{[^}]*\}/, '*').replaceAll(/\/$/, '')
    }

    /**
     * Returns attributes for a given request, if any exist.
     */
    Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        Assert.isTrue(object != null && supports(object.getClass()), "Object must be a FilterInvocation")

        FilterInvocation filterInvocation = (FilterInvocation) object

        String url = determineUrl(filterInvocation).replaceAll('/*$', '')

        Collection<ConfigAttribute> configAttributes
        try {
            configAttributes = findConfigAttributes(url, filterInvocation.request.method)
        }
        catch (RuntimeException e) {
            throw e
        }
        catch (Exception e) {
            throw new RuntimeException(e)
        }

        if ((configAttributes == null || configAttributes.isEmpty()) && rejectIfNoRule) {
            if (allow404 && !patterns.find { urlMatcher.match(it, url) }) {
                return ANONYMOUS
            }
            return DENY
        }

        return configAttributes
    }
}
