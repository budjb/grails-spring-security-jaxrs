/*
 * Copyright 2014-2015 Bud Byrd
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

import grails.plugin.springsecurity.ReflectionUtils
import org.codehaus.groovy.grails.commons.GrailsClass
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpMethod

import javax.ws.rs.*
import java.lang.annotation.Annotation
import java.lang.reflect.Method

class JaxrsAnnotationFilterInvocationDefinition extends JaxrsFilterInvocationDefinition {
    /**
     * Logger.
     */
    protected Logger log = LoggerFactory.getLogger(JaxrsAnnotationFilterInvocationDefinition)

    /**
     * Initializes patterns for a jaxrs resources and its patterns.
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
        if (findSecuredAnnotation(resource.annotations)) {
            classSecurity = getValue(findSecuredAnnotation(resource.annotations))
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

            // Build the pattern
            String pattern = buildPattern(classPath, resourcePath)

            // Store the pattern so we can determine if an endpoint actually exists or not
            patterns << pattern

            // Get the resource security config
            Collection<String> resourceSecurity = null
            if (findSecuredAnnotation(method.annotations)) {
                resourceSecurity = getValue(findSecuredAnnotation(method.annotations))
            }

            // If security was requested, add the pattern
            if (resourceSecurity || classSecurity) {
                log.trace("'$pattern' added to mapping")
                storeMapping(pattern, httpMethod, ReflectionUtils.buildConfigAttributes(resourceSecurity ?: classSecurity))
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

    protected Annotation findSecuredAnnotation(Annotation[] annotations) {
        log.debug(annotations.toString())
        Annotation annotation = annotations.find {
            it.annotationType() == grails.plugin.springsecurity.annotation.Secured.class
        }
        if (annotation != null) {
            log.debug('found grails @Secured annotation')
            return annotation
        }

        annotation = annotations.find {
            it.annotationType() == org.springframework.security.access.annotation.Secured.class
        }
        if (annotation != null) {
            log.debug('found spring security @Secured annotation')
            return annotation
        }

        return null
    }

    protected Collection<String> getValue(grails.plugin.springsecurity.annotation.Secured annotation) {
        return new LinkedHashSet<String>(Arrays.asList(annotation.value()))
    }

    protected Collection<String> getValue(org.springframework.security.access.annotation.Secured annotation) {
        return new LinkedHashSet<String>(Arrays.asList(annotation.value()))
    }
}
