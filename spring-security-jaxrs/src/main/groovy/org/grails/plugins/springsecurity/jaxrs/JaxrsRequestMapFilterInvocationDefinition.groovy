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
package org.grails.plugins.springsecurity.jaxrs

import grails.core.GrailsClass
import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.ReflectionUtils
import org.springframework.http.HttpMethod

/**
 * Request map object definition source.  Based on the Grails Spring Security version,
 * but adapted for use with JaxRS resources.
 */
class JaxrsRequestMapFilterInvocationDefinition extends JaxrsFilterInvocationDefinition {
    @Override
    void initialize(GrailsClass[] resourceClasses) {
        try {
            super.initialize(resourceClasses)
        }
        catch (RuntimeException e) {
            log.warn("Exception initializing; this is ok if it's at startup and due " +
                'to GORM not being initialized yet since the first web request will ' +
                're-initialize. Error message is: {}', e.message)
        }
    }

    /**
     * Resets the definition.
     *
     * @param grailsClasses
     */
    synchronized void reset(GrailsClass[] grailsClasses) {
        super.reset(grailsClasses)

        resetConfigs()

        loadRequestMaps().each { compileAndStoreMapping it }

        log.trace 'configs: {}', configAttributeMap
    }

    /**
     * Load request maps from database.
     */
    protected List<InterceptedUrl> loadRequestMaps() {
        boolean supportsHttpMethod = ReflectionUtils.requestmapClassSupportsHttpMethod()

        ReflectionUtils.loadAllRequestmaps().collect { requestmap ->
            String urlPattern = ReflectionUtils.getRequestmapUrl(requestmap)
            String configAttribute = ReflectionUtils.getRequestmapConfigAttribute(requestmap)
            HttpMethod method = supportsHttpMethod ? ReflectionUtils.getRequestmapHttpMethod(requestmap) : null
            new InterceptedUrl(urlPattern, split(configAttribute), method)
        }
    }
}
