/*
 * Copyright 2013 Bud Byrd
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

import org.apache.log4j.Logger

public enum AuthMethod {
    /**
     * Look for API keys from request headers.
     */
    HEADER,

    /**
     * Look for API keys from the URL query string.
     */
    QUERY

    /**
     * Logger.
     */
    private static Logger log = Logger.getLogger(AuthMethod.class)

    /**
     * Parse a list of values to a list of AuthMethod enums.
     *
     * @param values
     * @return
     */
    public static List<AuthMethod> parse(List values) {
        return parse(values as Object[])
    }

    /**
     * Parse an array of values to a list of AuthMethod enums.
     *
     * @param values
     * @return
     */
    public static List<AuthMethod> parse(Object[] values) {
        // If the list is null, pass back null
        if (values == null) {
            return null
        }

        // Attempt to convert each value
        List<AuthMethod> converted = values.collect {
            // If it's an AuthMethod, no work!
            if (it instanceof AuthMethod) {
                return it
            }

            // If it's a string, attempt to convert
            if (it instanceof String) {
                try {
                    return AuthMethod.valueOf(((String)it).toUpperCase())
                }
                catch (IllegalArgumentException e) {
                    log.warn("API auth method \"${it}\" is invalid")
                    return null
                }
            }

            // Warn of an invalid type
            log.warn("API auth method with type \"${it.getClass()}\" is invalid")
        }

        // Remove nulls
        converted -= null

        return converted
    }
}