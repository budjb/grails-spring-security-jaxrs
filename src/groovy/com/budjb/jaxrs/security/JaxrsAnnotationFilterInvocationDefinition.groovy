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

import org.apache.log4j.Logger
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.commons.GrailsClass
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder
import org.springframework.http.HttpMethod
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.util.Assert

import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.annotation.Secured
import grails.plugin.springsecurity.web.access.intercept.AnnotationFilterInvocationDefinition
import org.springframework.security.access.SecurityConfig

import java.lang.reflect.Method
import java.util.ArrayList
import java.util.Collection
import java.util.Collections

import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.HEAD
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path

class JaxrsAnnotationFilterInvocationDefinition extends AnnotationFilterInvocationDefinition {
    /**
     * Logger.
     */
    protected Logger log = Logger.getLogger(getClass())

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
     * Initializes patterns.
     */
    public void initialize(Object staticRules, UrlMappingsHolder mappingsHolder, GrailsClass[] controllerClasses) {
        // Call the parent
        super.initialize(staticRules, mappingsHolder, controllerClasses)

        // Initialize resources
        initializeJaxrs()
    }

    /**
     * Initializes patterns for jaxrs resources.
     */
    public void initializeJaxrs() {
        application.resourceClasses.each {
            initializeResource(it)
        }
    }

    /**
     * Initializes patterns for a jaxrs resources and its endpoints.
     *
     * @param clazz
     */
    protected void initializeResource(GrailsClass clazz) {
        // Grab the actual class
        Class resource = clazz.clazz

        // Get the base path of the resource
        String classPath = resource.getAnnotation(Path)?.value()

        // Get the base security config
        Collection<String> classSecurity = null
        if (findAnnotation(resource.annotations)) {
            classSecurity = getValue(findAnnotation(resource.annotations))
        }

        // Set up each resource method
        resource.declaredMethods.each { method ->
            // Get the resource path
            String resourcePath = method.getAnnotation(Path)?.value() ?: ''

            // Get the method
            HttpMethod httpMethod = getJaxrsHttpMethod(method)

            // No method, no security
            if (!httpMethod) {
                log.trace("'${buildPattern(classPath, resourcePath)}' does not have an HTTP method")
                return
            }

            // Get the resource security config
            Collection<String> resourceSecurity = null
            if (findAnnotation(method.annotations)) {
                resourceSecurity = getValue(findAnnotation(method.annotations))
            }

            // If security was requested, add the pattern
            if (resourceSecurity || classSecurity) {
                log.trace("'${buildPattern(classPath, resourcePath)}' added to mapping")
                storeMapping(buildPattern(classPath, resourcePath), httpMethod, ReflectionUtils.buildConfigAttributes(resourceSecurity ?: classSecurity))
            }
            else if (rejectIfNoRule) {
                log.trace("'${buildPattern(classPath, resourcePath)}' added to mapping as always deny")
                storeMapping(buildPattern(classPath, resourcePath), httpMethod, DENY)
            }
            else {
                log.trace("'${buildPattern(classPath, resourcePath)}' added to mapping as anonymous")
                storeMapping(buildPattern(classPath, resourcePath), httpMethod, ANONYMOUS)
            }
        }
    }

    /**
     * Returns the HTTP method of a given method.
     *
     * @param method
     * @return
     */
    protected HttpMethod getJaxrsHttpMethod(Method method) {
        if (method.getAnnotation(GET)) {
            return HttpMethod.GET
        }
        if (method.getAnnotation(POST)) {
            return HttpMethod.POST
        }
        if (method.getAnnotation(DELETE)) {
            return HttpMethod.DELETE
        }
        if (method.getAnnotation(PUT)) {
            return HttpMethod.PUT
        }
        if (method.getAnnotation(HEAD)) {
            return HttpMethod.HEAD
        }

        return null
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
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        // Sanity check the input
        Assert.isTrue(object != null && supports(object.getClass()), "Object must be a FilterInvocation")

        // Cast the object
        FilterInvocation filterInvocation = (FilterInvocation)object

        // Allow the parent to determine the URL based on controller/action
        String url = determineUrl(filterInvocation)

        // Attempt to find a match for attributes
        Collection<ConfigAttribute> configAttributes
        try {
            // If the controller is jaxrs, run the find method specific to resources.
            // Otherwise, use the normal find method.
            if (url =~ '^/(jaxrs|jaxrs/.*)$') {
                url = filterInvocation.request.forwardURI - filterInvocation.request.contextPath
                configAttributes = findJaxrsConfigAttributes(url, filterInvocation.request.method)
            }
            else {
                configAttributes = findConfigAttributes(url, filterInvocation.request.method)
            }
        }
        catch (RuntimeException e) {
            throw e
        }
        catch (Exception e) {
            throw new RuntimeException(e)
        }

        // If no rule was found, this should be a resource that doesn't exist,
        // so allow it through auth so it can 404.
        if (configAttributes == null) {
            return ANONYMOUS
        }

        // Always deny empty configs
        if (configAttributes.isEmpty()) {
            return DENY
        }

        return configAttributes
    }

    /**
     * Attempts to find a set of config attributes that matches a given URL.
     *
     * @param url
     * @param requestMethod
     * @return
     * @throws Exception
     */
    protected Collection<ConfigAttribute> findJaxrsConfigAttributes(final String url, final String requestMethod) throws Exception {
        // Run init
        initialize()

        // Match markers
        InterceptedUrl match

        // Whether to stop when a first match is found
        boolean stopAtFirstMatch = stopAtFirstMatch()

        // Iterate through all known stored patterns
        for (InterceptedUrl candidate : compiled) {
            // Skip if the HTTP method doesn't match
            if (candidate.getHttpMethod() != null && requestMethod != null && candidate.getHttpMethod() != HttpMethod.valueOf(requestMethod)) {
                log.trace("Request '${requestMethod} ${url}' doesn't match '${candidate.httpMethod} ${candidate.pattern}'")
                continue
            }

            // Check for a URL match
            if (urlMatcher.match(candidate.getPattern(), url)) {
                // Determine if the candidate is absolute
                boolean isCandidateAbsolute = !candidate.pattern.contains('*')

                // Determine if the match is absolute
                boolean isMatchAbsolute = match == null ? false : !match.pattern.contains('*')

                // Log the possible candidate
                log.trace("possible candidate for '${url}': '${candidate.pattern}':${candidate.configAttributes}")

                // If this is a first match or the pattern is identical, process it
                if (!match || (isCandidateAbsolute && !isMatchAbsolute) || (!stopAtFirstMatch && isCandidateAbsolute == isMatchAbsolute)) {
                    // Store the match
                    match = candidate

                    // Log it
                    log.trace("new candidate for '${url}': '${candidate.pattern}':${candidate.configAttributes}")
                }
            }
        }

        // Log the result
        if (!match) {
            log.trace("no config for '${url}'")
        }
        else {
            log.trace("config for '${url}' is '${match.pattern}':${match.configAttributes}")
        }

        return match?.configAttributes
    }
}
