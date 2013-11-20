package com.budjb.jaxrs.security.annotation

import java.lang.annotation.*
import com.budjb.jaxrs.security.AuthType

@Target([ElementType.METHOD, ElementType.TYPE])
@Retention(RetentionPolicy.RUNTIME)
public @interface Auth {
    AuthType[] value() default []
}
