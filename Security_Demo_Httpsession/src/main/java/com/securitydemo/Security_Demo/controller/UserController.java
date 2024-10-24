package com.securitydemo.Security_Demo.controller;

import java.security.Principal;
import java.util.Base64;
import java.util.Objects;


import com.securitydemo.Security_Demo.dto.ChangePasswordRequest;
import com.securitydemo.Security_Demo.dto.UserDto;
import com.securitydemo.Security_Demo.entity.User;
import com.securitydemo.Security_Demo.service.OTPService;
import com.securitydemo.Security_Demo.service.CustomUserDetailsService;
import com.securitydemo.Security_Demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class UserController {


    private final CustomUserDetailsService customUserDetailsService;
    private final OTPService otpService;
    private final UserService userService;


    @Autowired
    public UserController(CustomUserDetailsService customUserDetailsService, UserService userService, OTPService otpService) {
        this.customUserDetailsService = customUserDetailsService;
        this.userService = userService;
        this.otpService = otpService;
    }

    @GetMapping("/home")
    public String home(Model model, Principal principal) {
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(principal.getName());
        model.addAttribute("userdetail", userDetails);
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model, UserDto userDto) {
        model.addAttribute("user", userDto);
        return "register";
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerSave(@ModelAttribute("user") UserDto userDto, Model model) {
        User user = userService.findByUsername(userDto.getUsername());
        if (user != null) {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/register?userexist");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }
        // Generate TOTP secret key
        String secret = otpService.generateKey();

        // Generate QR code URL
        String qrCodeUrl = otpService.generateQRUrl(secret, userDto.getUsername());

        userService.save(userDto,secret);

        // Return the secret and QR code URL to the client

        byte[] imageBytes = Base64.getDecoder().decode(qrCodeUrl);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_PNG);
        headers.setContentLength(imageBytes.length);

        return new ResponseEntity<>(imageBytes, headers, HttpStatus.OK);
    }

    @GetMapping("/change-password")
    public String changePasswordForm(Model model, ChangePasswordRequest changePasswordRequest) {
        model.addAttribute("password", changePasswordRequest);
        return "change-password"; // Nome del file HTML per il form di cambio password
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@ModelAttribute("password") ChangePasswordRequest changePasswordRequest, Principal principal, Model model) {
        String username = principal.getName();
        if (Objects.equals(changePasswordRequest.getNewPassword(), changePasswordRequest.getconfirmPassword())){
            userService.changePassword(username, changePasswordRequest);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/home");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }
        else {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/change-password?notmatch");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);

        }

    }

}
