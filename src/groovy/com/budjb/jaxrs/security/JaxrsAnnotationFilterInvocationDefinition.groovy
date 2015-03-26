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
import groovy.transform.CompileStatic
import groovy.transform.TypeCheckingMode
import org.codehaus.groovy.grails.commons.GrailsClass
import org.springframework.http.HttpMethod

import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.HEAD
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path
import java.lang.annotation.Annotation
import java.lang.reflect.Method

/**
 * Annotation-based object definition source.  Based on the Grails Spring Security version,
 * but adapted for use with JaxRS resources.
 */
@CompileStatic
class JaxrsAnnotationFilterInvocationDefinition extends JaxrsFilterInvocationDefinition {

    /**
     * Initializes patterns for a jaxrs resources and its patterns.
     */
    protected void initializeResource(GrailsClass clazz) {
        Class resource = clazz.clazz

        String classPath = resource.getAnnotation(Path)?.value()

        Collection<String> classSecurity = getAnnotationValues(resource.annotations)

        resource.declaredMethods.each { Method method ->
            String resourcePath = method.getAnnotation(Path)?.value() ?: ''

            HttpMethod httpMethod = getJaxrsHttpMethod(method)
            if (!httpMethod) {
                return
            }

            String pattern = buildPattern(classPath, resourcePath)

            patterns << pattern

            Collection<String> resourceSecurity = getAnnotationValues(method.annotations)

            if (resourceSecurity || classSecurity) {
                storeMapping(pattern, httpMethod, ReflectionUtils.buildConfigAttributes(resourceSecurity ?: classSecurity))
            }
        }
    }

    @CompileStatic(TypeCheckingMode.SKIP)
    protected Collection<String> getAnnotationValues(Annotation[] annotations) {
        Annotation a = findSecuredAnnotation(annotations)
        if (a) getValue a
    }

    /**
     * Returns the HTTP method of a given method.
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
    }

    /**
     * Find an appropriate @Secured annotation give a list of annotations.
     */
    protected Annotation findSecuredAnnotation(Annotation[] annotations) {
        Annotation annotation = annotations.find {
            it.annotationType() == grails.plugin.springsecurity.annotation.Secured.class
        }
        if (annotation) {
            return annotation
        }

        return annotations.find {
            it.annotationType() == org.springframework.security.access.annotation.Secured.class
        }
    }

    /**
     * Returns the value of a @Secured annotation.
     */
    protected Collection<String> getValue(grails.plugin.springsecurity.annotation.Secured annotation) {
        return Arrays.asList(annotation.value()) as Set
    }

    /**
     * Returns the value of a @Secured annotation.
     */
    protected Collection<String> getValue(org.springframework.security.access.annotation.Secured annotation) {
        return Arrays.asList(annotation.value()) as Set
    }
}
