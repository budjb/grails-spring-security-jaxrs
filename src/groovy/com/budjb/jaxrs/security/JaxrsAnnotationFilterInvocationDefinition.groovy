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

/**
 * Annotation-based object definition source.  Based on the Grails Spring Security version,
 * but adapted for use with JaxRS resources.
 */
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
        Class resource = clazz.clazz

        String classPath = resource.getAnnotation(Path)?.value()

        Collection<String> classSecurity = null
        if (findSecuredAnnotation(resource.annotations)) {
            classSecurity = getValue(findSecuredAnnotation(resource.annotations))
        }

        resource.declaredMethods.each { method ->
            String resourcePath = method.getAnnotation(Path)?.value() ?: ''

            HttpMethod httpMethod = getJaxrsHttpMethod(method)

            if (!httpMethod) {
                return
            }

            String pattern = buildPattern(classPath, resourcePath)

            patterns << pattern

            Collection<String> resourceSecurity = null
            if (findSecuredAnnotation(method.annotations)) {
                resourceSecurity = getValue(findSecuredAnnotation(method.annotations))
            }

            if (resourceSecurity || classSecurity) {
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

    /**
     * Find an appropriate @Secured annotation give a list of annotations.
     *
     * @param annotations
     * @return
     */
    protected Annotation findSecuredAnnotation(Annotation[] annotations) {
        Annotation annotation = annotations.find {
            it.annotationType() == grails.plugin.springsecurity.annotation.Secured.class
        }
        if (annotation != null) {
            return annotation
        }

        annotation = annotations.find {
            it.annotationType() == org.springframework.security.access.annotation.Secured.class
        }
        if (annotation != null) {
            return annotation
        }

        return null
    }

    /**
     * Returns the value of a @Secured annotation.
     *
     * @param annotation
     * @return
     */
    protected Collection<String> getValue(grails.plugin.springsecurity.annotation.Secured annotation) {
        return new LinkedHashSet<String>(Arrays.asList(annotation.value()))
    }

    /**
     * Returns the value of a @Secured annotation.
     *
     * @param annotation
     * @return
     */
    protected Collection<String> getValue(org.springframework.security.access.annotation.Secured annotation) {
        return new LinkedHashSet<String>(Arrays.asList(annotation.value()))
    }
}
