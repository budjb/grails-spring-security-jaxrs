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


    @Override
    Collection<ConfigAttribute> getAllConfigAttributes() {
        return sources.collect { it.getAllConfigAttributes() }
    }

    @Override
    boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz)
    }

    void register(FilterInvocationSecurityMetadataSource source) {
        log.debug('registering object definition source {}', source.getClass().simpleName)
        sources << source
    }

    void unregister(FilterInvocationSecurityMetadataSource source) {
        log.debug('un-registering object definition source {}', source.getClass().simpleName)
        sources -= source
    }
}
