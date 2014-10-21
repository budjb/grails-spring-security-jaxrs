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

import java.util.Collection

import org.apache.log4j.Logger;
import org.springframework.http.HttpMethod
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.util.Assert

import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.web.access.intercept.RequestmapFilterInvocationDefinition

class JaxrsRequestmapFilterInvocationDefinition extends RequestmapFilterInvocationDefinition {
    /**
     * Logger.
     */
    protected Logger log = Logger.getLogger(getClass())

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
                url = url.replaceAll('/$', '')
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

        if ((configAttributes == null || configAttributes.isEmpty()) && rejectIfNoRule) {
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
