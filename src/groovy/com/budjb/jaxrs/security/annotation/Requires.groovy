package com.budjb.jaxrs.security.annotation

import java.lang.annotation.*

@Target([ElementType.METHOD, ElementType.TYPE])
@Retention(RetentionPolicy.RUNTIME)
public @interface Requires {
    String[] value() default []
}
