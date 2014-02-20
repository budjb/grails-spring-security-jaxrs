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

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.commons.GrailsClass
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder
import org.springframework.http.HttpMethod
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.util.Assert

import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.annotation.Secured
import grails.plugin.springsecurity.web.access.intercept.AnnotationFilterInvocationDefinition

import java.lang.reflect.Method
import java.util.Collection

import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.HEAD
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path

class JaxrsAnnotationFilterInvocationDefinition extends AnnotationFilterInvocationDefinition {
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
            // Get the method
            HttpMethod httpMethod = getJaxrsHttpMethod(method)

            // No method, no security
            if (!httpMethod) {
                return
            }

            // Get the resource path
            String resourcePath = method.getAnnotation(Path)?.value() ?: ''

            // Get the resource security config
            Collection<String> resourceSecurity = null
            if (findAnnotation(method.annotations)) {
                resourceSecurity = getValue(findAnnotation(method.annotations))
            }

            // If security was requested, add the pattern
            if (resourceSecurity || classSecurity) {
                storeMapping(buildPattern(classPath, resourcePath), httpMethod, ReflectionUtils.buildConfigAttributes(resourceSecurity ?: classSecurity))
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
        return "${base ?: ''}/${resource ?: ''}".replaceAll(/\/+/, '/').replaceAll(/\{.*\}/, '*').replaceAll(/\/$/, '')
    }

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
