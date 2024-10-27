package com.securitydemo.Security_Demo.service;

import com.securitydemo.Security_Demo.dto.ChangePasswordRequest;
import com.securitydemo.Security_Demo.dto.UserDto;
import com.securitydemo.Security_Demo.entity.User;
import com.securitydemo.Security_Demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class UserServiceImpl implements UserService {
    @Autowired
    PasswordEncoder passwordEncoder;
    private UserRepository userRepository;
    public UserServiceImpl(UserRepository userRepository) {
        super();
        this.userRepository = userRepository;
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User save(UserDto userDto, String authkey) {
        User user = new User(userDto.getUsername(), passwordEncoder.encode(userDto.getPassword()),
                userDto.getFullname(),authkey);
        return userRepository.save(user);
    }

    @Override
    public void changePassword(String username, ChangePasswordRequest changePasswordRequest) {
        User user = userRepository.findByUsername(username);
        if (user == null || !passwordEncoder.matches(changePasswordRequest.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid old password");
        }
        user.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));
        userRepository.save(user);
    }



}
