package com.securitydemo.Security_Demo.config;
import com.securitydemo.Security_Demo.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import com.securitydemo.Security_Demo.service.CustomUserDetailsService;
import java.io.IOException;

public class CustomAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final CustomUserDetailsService customUserDetailsService;
    public CustomAuthenticationSuccessHandler(JwtService jwtService, CustomUserDetailsService customUserDetailsService){
        this.jwtService = jwtService;
        this.customUserDetailsService = customUserDetailsService;

    }
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        System.out.println("Logged user: " + authentication.getName());
        CustomUserDetails loadedUser;
        try {
            loadedUser = customUserDetailsService.loadUserByUsername(authentication.getName());
        } catch (Exception repositoryProblem) {
            throw new InternalAuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }

        String jwtToken = jwtService.generateToken(loadedUser);

        Cookie cookie = new Cookie("jwtToken", jwtToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        response.sendRedirect("/home");
    }
}
