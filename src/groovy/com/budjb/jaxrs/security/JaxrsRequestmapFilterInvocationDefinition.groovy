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
import org.codehaus.groovy.grails.commons.GrailsClass
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpMethod

class JaxrsRequestmapFilterInvocationDefinition extends JaxrsFilterInvocationDefinition {
    /**
     * Logger.
     */
    protected Logger log = LoggerFactory.getLogger(JaxrsRequestmapFilterInvocationDefinition)

    /**
     * Initialize security rules.
     *
     * @param resourceClasses
     */
    @Override
    void initialize(GrailsClass[] resourceClasses) {
        super.initialize(resourceClasses)

        try {
            resetConfigs()

            loadRequestmaps().each {
                compileAndStoreMapping(it)
            }

            if (log.isTraceEnabled()) {
                log.trace("configs: {}", getConfigAttributeMap())
            }
        }
        catch (RuntimeException e) {
            log.warn("Exception initializing; this is ok if it's at startup and due " +
                "to GORM not being initialized yet since the first web request will " +
                "re-initialize. Error message is: {}", e.getMessage())
        }
    }

    /**
     * Load request maps from database.
     *
     * @return
     */
    protected List<InterceptedUrl> loadRequestmaps() {
        List<InterceptedUrl> data = new ArrayList<InterceptedUrl>()

        boolean supportsHttpMethod = ReflectionUtils.requestmapClassSupportsHttpMethod()

        ReflectionUtils.loadAllRequestmaps().each {
            String urlPattern = ReflectionUtils.getRequestmapUrl(it)
            String configAttribute = ReflectionUtils.getRequestmapConfigAttribute(it)
            HttpMethod method = supportsHttpMethod ? ReflectionUtils.getRequestmapHttpMethod(it) : null
            data.add(new InterceptedUrl(urlPattern, split(configAttribute), method))
        }

        return data
    }
}
