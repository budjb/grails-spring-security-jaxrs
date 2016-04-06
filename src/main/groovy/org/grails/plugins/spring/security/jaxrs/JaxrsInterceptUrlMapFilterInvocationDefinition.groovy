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
package org.grails.plugins.spring.security.jaxrs

import grails.core.GrailsClass
import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.ReflectionUtils

/**
 * Intercept URL object definition source.  Based on the Grails Spring Security version,
 * but adapted for use with JaxRS resources.
 */
class JaxrsInterceptUrlMapFilterInvocationDefinition extends JaxrsFilterInvocationDefinition {
    @Override
    synchronized void reset(GrailsClass[] resourceClasses) {
        super.reset(resourceClasses)

        def interceptUrlMap = getInterceptUrlMap()

        if (interceptUrlMap instanceof Map) {
            throw new IllegalArgumentException("interceptUrlMap defined as a Map is not supported; must be specified as a " +
                "List of Maps as described in section 'Configuring Request Mappings to Secure URLs' of the reference documentation" +
                "for the spring-security-core plugin")
        }

        if (!(interceptUrlMap instanceof List)) {
            log.warn "interceptUrlMap config property isn't a List of Maps"
            return
        }

        ReflectionUtils.splitMap((List<Map<String, Object>>) interceptUrlMap).each { InterceptedUrl iu -> compileAndStoreMapping iu }

        log.trace 'configs: {}', configAttributeMap
    }

    /**
     * Always stop at first match.
     */
    @Override
    protected boolean stopAtFirstMatch() {
        return true
    }

    /**
     * Retrieve the configuration for the intercept URL map.
     *
     * @return
     */
    def getInterceptUrlMap() {
        ReflectionUtils.getConfigProperty('interceptUrlMap')
    }
}
