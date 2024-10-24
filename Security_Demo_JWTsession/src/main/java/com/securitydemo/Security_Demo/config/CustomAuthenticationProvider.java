package com.securitydemo.Security_Demo.config;
import com.securitydemo.Security_Demo.service.CustomUserDetailsService;
import com.securitydemo.Security_Demo.service.OTPService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OTPService otpService;

    @Autowired
    public CustomAuthenticationProvider (CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder, OTPService otpService) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.otpService = otpService;

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthenticationToken auth = (CustomAuthenticationToken) authentication;
        CustomUserDetails loadedUser;
        try {
            loadedUser = userDetailsService.loadUserByUsername(auth.getPrincipal().toString());
        } catch (Exception repositoryProblem) {
            throw new InternalAuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }

        if (!passwordEncoder.matches(authentication.getCredentials().toString(), loadedUser.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }
        if(!otpService.isValid(loadedUser.getAuthkey(), auth.getOtpCode())){
            throw new BadCredentialsException("Invalid OTP code");
        }


        return new UsernamePasswordAuthenticationToken(loadedUser.getUsername(), loadedUser.getPassword(), loadedUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthenticationToken.class.isAssignableFrom(authentication);
    }
}