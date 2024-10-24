package com.securitydemo.Security_Demo.service;
import com.securitydemo.Security_Demo.dto.ChangePasswordRequest;
import com.securitydemo.Security_Demo.dto.UserDto;
import com.securitydemo.Security_Demo.entity.User;

public interface UserService {
    User findByUsername(String username);
    User save(UserDto userDto, String authkey);
    void changePassword(String username, ChangePasswordRequest changePasswordRequest);
}


