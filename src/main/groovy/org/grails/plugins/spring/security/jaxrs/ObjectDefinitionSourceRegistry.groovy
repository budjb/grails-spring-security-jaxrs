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
package org.grails.plugins.spring.security.jaxrs

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource

/**
 * A class that contains multiple metadata sources. This allows multiple implementations
 * of request types to be considered for security annotations, as the default Grails implementation
 * only considers controllers.
 */
class ObjectDefinitionSourceRegistry implements FilterInvocationSecurityMetadataSource {
    /**
     * Logger.
     */
    Logger log = LoggerFactory.getLogger(ObjectDefinitionSourceRegistry)

    /**
     * DENY config rule.
     *
     * This is brought over from {@see AbstractFilterInvocationDefintion}.
     */
    protected static
    final Collection<ConfigAttribute> DENY = Collections.singletonList((ConfigAttribute) new SecurityConfig("_DENY_"))

    /**
     * Whether to reject the request if no rule is found.
     */
    boolean rejectIfNoRule

    /**
     * Contains all registered object definition sources.
     */
    List<FilterInvocationSecurityMetadataSource> sources = []

    /**
     * Accesses the {@code ConfigAttribute}s that apply to a given secure object.
     *
     * @param object the object being secured
     *
     * @return the attributes that apply to the passed in secured object. Should return an
     * empty collection if there are no applicable attributes.
     *
     * @throws IllegalArgumentException if the passed object is not of a type supported by
     * the <code>SecurityMetadataSource</code> implementation
     */
    @Override
    Collection<ConfigAttribute> getAttributes(o) throws IllegalArgumentException {
        for (FilterInvocationSecurityMetadataSource source : sources) {
            log.debug('retrieving security attributes using object definition source {}', source.getClass().simpleName)

            Collection<ConfigAttribute> configAttributes = source.getAttributes(o)
            if (!configAttributes) {
                continue
            }

            if (configAttributes.size() != 1 || configAttributes[0].attribute != '_DENY_') {
                return configAttributes
            }
        }

        if (rejectIfNoRule) {
            return DENY
        }

        return []
    }

    /**
     * If available, returns all of the {@code ConfigAttribute}s defined by the
     * implementing class.
     * <p>
     * This is used by the {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor}
     * to perform startup time validation of each {@code ConfigAttribute} configured against it.
     *
     * @return the {@code ConfigAttribute}s or {@code null} if unsupported
     */
    @Override
    List getAllConfigAttributes() {
        return sources.collect { it.allConfigAttributes }.flatten()
    }

    /**
     * Indicates whether the {@code SecurityMetadataSource} implementation is able to
     * provide {@code ConfigAttribute}s for the indicated secure object type.
     *
     * @param clazz the class that is being queried
     *
     * @return true if the implementation can process the indicated class
     */
    @Override
    boolean supports(Class<?> clazz) {
        return FilterInvocation.isAssignableFrom(clazz)
    }

    /**
     * Registers an object definition source.
     *
     * @param source New metadata source to add to the registry.
     */
    void register(FilterInvocationSecurityMetadataSource source) {
        log.debug('registering object definition source {}', source.getClass().simpleName)
        sources << source
    }
}
