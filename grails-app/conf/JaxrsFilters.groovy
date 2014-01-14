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
import com.budjb.jaxrs.security.JaxrsSecurityContext
import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException
import org.apache.log4j.Logger

class JaxrsFilters {
    /**
     * Logger
     */
    Logger log = Logger.getLogger('com.budjb.jaxrs.security.JaxrsFilters')

    /**
     * Security context holder
     */
    JaxrsSecurityContext jaxrsSecurityContext

    def filters = {
        all(controller: 'jaxrs', action: '*') {
            before = {
                try {
                    jaxrsSecurityContext.process(request)
                }
                catch (UnauthorizedClientException e) {
                    render template: '/jaxrs/unauthorized', model: [message: e.message], status: 401
                    return false
                }
                catch(ForbiddenClientException e) {
                    render template: '/jaxrs/forbidden', model: [message: e.message], status: 403
                    return false
                }
                catch (Exception e) {
                    log.error("unexpected error occurred while processing request through JaxrsFilters", e)
                    render template: '/jaxrs/error', model: [message: e.message], status: 500
                    return false
                }
            }
        }
    }
}
