/*
 * Copyright 2013 Bud Byrd
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

import java.lang.reflect.Method

import com.budjb.jaxrs.security.annotation.Requires
import com.budjb.jaxrs.security.annotation.AllowAnonymous
import com.budjb.jaxrs.security.annotation.AuthMethods

import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.HEAD
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path

import org.apache.log4j.Logger
import org.grails.jaxrs.DefaultGrailsResourceClass

class ResourceSecurityContext {
    /**
     * URL pattern of a resource.
     */
    String pattern

    /**
     * HTTP method of a resource.
     */
    Class method

    /**
     * List of roles required for the resource.
     */
    List<String> roles

    /**
     * Whether to skip authentication.
     */
    boolean allowAnonymous

    /**
     * List of acceptable api key authentication types.
     */
    List<AuthMethod> authMethods

    /**
     * Logger.
     */
    static private Logger log = Logger.getLogger(ResourceSecurityContext.class)

    /**
     * Whether the pattern is absolute.
     */
    public boolean getIsAbsolute() {
        return pattern.contains('.*')
    }

    /**
     * Determines whether the given URL path matches the pattern for this context.
     *
     * @param path
     * @return
     */
    public boolean match(String path) {
        return path ==~ pattern
    }

    /**
     * Builds a list of security contexts for a given resource.
     *
     * @param clazz
     * @return
     */
    public static build(DefaultGrailsResourceClass clazz) {
        // Track security contexts
        List<ResourceSecurityContext> contexts = []

        // Grab the actual class
        Class resource = clazz.clazz

        // Get the base path of the resource
        String basePath = resource.getAnnotation(Path)?.value()

        // Get the base security config
        List baseSecurity = resource.getAnnotation(Requires)?.value()

        // Get the base auth methods config
        List baseAuthMethods = AuthMethod.parse(resource.getAnnotation(AuthMethods)?.value())

        // Set up each resource method
        resource.declaredMethods.each { method ->
            // Get the method
            Class httpMethod = getHttpMethod(method)

            // No method, no security
            if (!httpMethod) {
                return
            }

            // Get the resource path
            String resourcePath = method.getAnnotation(Path)?.value() ?: ''

            // Get the resource security config
            List resourceSecurity = method.getAnnotation(Requires)?.value()

            // Get the resource auth methods config
            List resourceAuthMethods = AuthMethod.parse(method.getAnnotation(AuthMethods)?.value())

            // Store the security context
            contexts << new ResourceSecurityContext(
                pattern: buildPattern(basePath, resourcePath),
                roles: resourceSecurity ?: baseSecurity ?: [],
                method: httpMethod,
                allowAnonymous: method.getAnnotation(AllowAnonymous) ? true : false,
                authMethods: resourceAuthMethods ?: baseAuthMethods ?: []
            )
        }

        return contexts
    }

    /**
     * Returns the HTTP method of a given method.
     *
     * @param method
     * @return
     */
    protected static Class getHttpMethod(Method method) {
        if (method.getAnnotation(GET)) {
            return GET
        }
        if (method.getAnnotation(POST)) {
            return POST
        }
        if (method.getAnnotation(DELETE)) {
            return DELETE
        }
        if (method.getAnnotation(PUT)) {
            return PUT
        }
        if (method.getAnnotation(HEAD)) {
            return HEAD
        }

        return null
    }

    /**
     * Replace multiple slashes with one slash, and template path pieces with a .* regex.
     *
     * @param path
     * @return
     */
    protected static buildPattern(String base, String resource) {
        return "${base ?: ''}/${resource ?: ''}".replaceAll(/\/+/, '/').replaceAll(/\{.*\}/, '.*').replaceAll(/\/$/, '')
    }
}
