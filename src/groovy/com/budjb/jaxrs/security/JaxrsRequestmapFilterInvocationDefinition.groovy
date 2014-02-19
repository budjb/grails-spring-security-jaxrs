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

import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.util.Assert

import grails.plugin.springsecurity.web.access.intercept.RequestmapFilterInvocationDefinition

class JaxrsRequestmapFilterInvocationDefinition extends RequestmapFilterInvocationDefinition {
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
