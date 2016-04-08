package org.grails.plugins.springsecurity.jaxrs.test

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.GenericFilterBean

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

class RequestRoleFilter extends GenericFilterBean {
    @Autowired
    AuthenticationManager authenticationManager

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String role = request.getHeader('role')

        if (role) {
            try {
                SecurityContextHolder.getContext().setAuthentication(
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(role, role))
                )
            }
            catch (Exception e) {
                SecurityContextHolder.clearContext()
            }
        }

        chain.doFilter(request, response)
    }
}
