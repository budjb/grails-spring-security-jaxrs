import org.grails.plugins.springsecurity.jaxrs.test.RequestRoleAuthenticationProvider
import org.grails.plugins.springsecurity.jaxrs.test.RequestRoleFilter
import org.springframework.boot.autoconfigure.security.Http401AuthenticationEntryPoint
import org.springframework.security.web.access.AccessDeniedHandlerImpl

// Place your Spring DSL code here
beans = {
    authenticationEntryPoint(Http401AuthenticationEntryPoint, 'sorry')
    accessDeniedHandler(AccessDeniedHandlerImpl)
    requestRoleAuthenticationProvider(RequestRoleAuthenticationProvider)
    requestRoleFilter(RequestRoleFilter) {
        authenticationManager = ref('authenticationManager')
    }
}
