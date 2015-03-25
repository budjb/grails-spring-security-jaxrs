/*
 * Copyright 2015 Bud Byrd
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

import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.web.access.intercept.AbstractFilterInvocationDefinition
import org.codehaus.groovy.grails.commons.GrailsClass
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpMethod
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.FilterInvocation
import org.springframework.util.Assert

import javax.ws.rs.Path

class JaxrsFilterInvocationDefinition extends AbstractFilterInvocationDefinition {
    /**
     * Logger.
     */
    Logger log = LoggerFactory.getLogger(JaxrsFilterInvocationDefinition)

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
    protected List<String> patterns = []

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

    /**
     * Attempts to find a set of config attributes that matches a given URL.
     *
     * @param url
     * @param requestMethod
     * @return
     * @throws Exception
     */
    protected Collection<ConfigAttribute> findConfigAttributes(
        final String url, final String requestMethod) throws Exception {
        initialize()

        InterceptedUrl match
        boolean isMatchAbsolute
        boolean stopAtFirstMatch = stopAtFirstMatch()

        compiled.each { candidate ->
            if (candidate.getHttpMethod() != null && requestMethod != null && candidate.getHttpMethod() != HttpMethod.valueOf(requestMethod)) {
                log.trace("Request '{} {}' doesn't match '{} {}'", requestMethod, url, candidate.httpMethod, candidate.pattern)
                return
            }

            if (urlMatcher.match(candidate.getPattern(), url)) {
                boolean isCandidateAbsolute = !candidate.pattern.contains('*')

                log.trace("possible candidate for '{}': '{}':{}", url, candidate.pattern, candidate.configAttributes)

                if (!match || (isCandidateAbsolute && !isMatchAbsolute) || (!stopAtFirstMatch && isCandidateAbsolute == isMatchAbsolute)) {
                    match = candidate
                    isMatchAbsolute = !match.pattern.contains('*')
                    log.trace("new candidate for '{}': '{}':{}", url, candidate.pattern, candidate.configAttributes)
                }
            }
        }

        if (!match) {
            log.trace("no config for '{}'", url)
            return null
        }

        log.trace("config for '{}' is '{}':{}", url, match.pattern, match.configAttributes)
        return match.configAttributes
    }
}
