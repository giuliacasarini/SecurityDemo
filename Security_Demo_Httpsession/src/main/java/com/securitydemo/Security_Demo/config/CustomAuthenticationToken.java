package com.securitydemo.Security_Demo.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CustomAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final Integer otpCode;

    public CustomAuthenticationToken(Object principal, Object credentials, Integer otpCode) {
        super(principal, credentials);
        this.otpCode = otpCode;
        super.setAuthenticated(false);
    }

    public CustomAuthenticationToken(Object principal, Object credentials,
                                                 Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.otpCode = 0;
    }

    public Integer getOtpCode() {
        return otpCode;
    }
}
