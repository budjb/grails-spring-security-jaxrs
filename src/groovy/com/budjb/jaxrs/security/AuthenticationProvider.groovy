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

import com.budjb.jaxrs.security.exception.ForbiddenClientException
import com.budjb.jaxrs.security.exception.UnauthorizedClientException
import javax.servlet.http.HttpServletRequest

abstract class AuthenticationProvider {
    /**
     * Return the name of this provider.
     *
     * @return
     */
    public abstract String getKey()

    /**
     * Returns the name of the client "type" used to identify users along with their principal identity.
     *
     * @return
     */
    public abstract String getClientType()

    /**
     * Attempts to authenticate the user given a request.
     *
     * @param request
     * @return
     */
    public abstract ClientSecurityContext authenticate(HttpServletRequest request) throws UnauthorizedClientException, ForbiddenClientException
}
