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

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource

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
    protected static final Collection<ConfigAttribute> DENY
    static {
        Collection<ConfigAttribute> list = new ArrayList<ConfigAttribute>(1)
        list.add(new SecurityConfig("_DENY_"))
        DENY = Collections.unmodifiableCollection(list)
    }

    /**
     * Whether to reject the request if no rule is found.
     */
    boolean rejectIfNoRule

    /**
     * Contains all registered object definition sources.
     */
    List<FilterInvocationSecurityMetadataSource> sources

    /**
     * Constructor
     */
    ObjectDefinitionSourceRegistry() {
        sources = new LinkedList<FilterInvocationSecurityMetadataSource>()
    }

    /**
     * Returns a list of rules for a given object.
     *
     * @param o
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        for (FilterInvocationSecurityMetadataSource source : sources) {
            log.debug('retrieving security attributes using object definition source {}', source.getClass().simpleName)

            Collection<ConfigAttribute> configAttributes = source.getAttributes(o)

            if (configAttributes == null || configAttributes.isEmpty()) {
                continue
            }

            if (configAttributes.size() == 1 && configAttributes[0].getAttribute() == '_DENY_') {
                continue
            }

            return configAttributes
        }

        if (rejectIfNoRule) {
            return DENY
        }

        return null
    }

    /**
     * Returns all config attributes.
     *
     * @return
     */
    @Override
    Collection<ConfigAttribute> getAllConfigAttributes() {
        return sources.collect { it.getAllConfigAttributes() }
    }

    /**
     * Class support.
     *
     * @param clazz
     * @return
     */
    @Override
    boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz)
    }

    /**
     * Registers an object definition source.
     *
     * @param source
     */
    void register(FilterInvocationSecurityMetadataSource source) {
        log.debug('registering object definition source {}', source.getClass().simpleName)
        sources << source
    }

    /**
     * Un-registers an object definition source.
     *
     * @param source
     */
    void unregister(FilterInvocationSecurityMetadataSource source) {
        log.debug('un-registering object definition source {}', source.getClass().simpleName)
        sources -= source
    }
}
