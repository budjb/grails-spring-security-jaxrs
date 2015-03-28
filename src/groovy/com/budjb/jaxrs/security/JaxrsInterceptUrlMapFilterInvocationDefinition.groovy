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

import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.ReflectionUtils
import groovy.transform.CompileStatic
import org.codehaus.groovy.grails.commons.GrailsClass

/**
 * Intercept URL object definition source.  Based on the Grails Spring Security version,
 * but adapted for use with JaxRS resources.
 */
class JaxrsInterceptUrlMapFilterInvocationDefinition extends JaxrsFilterInvocationDefinition {
    @Override
    void initialize(GrailsClass[] resourceClasses) {
        super.initialize(resourceClasses)

        def map = ReflectionUtils.getConfigProperty("interceptUrlMap")

        if (!(map instanceof Map || map instanceof List)) {
            log.warn("interceptUrlMap config property isn't a Map or a List of Maps")
            return
        }

        List<InterceptedUrl> urls = ReflectionUtils.splitMap(map)

        resetConfigs()

        urls.each { InterceptedUrl iu -> compileAndStoreMapping iu }
    }

    /**
     * Always stop at first match.
     */
    @Override
    protected boolean stopAtFirstMatch() {
        return true
    }
}
