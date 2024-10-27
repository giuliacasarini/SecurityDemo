package com.securitydemo.Security_Demo.repository;
import com.securitydemo.Security_Demo.dto.UserDto;
import com.securitydemo.Security_Demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    User save(UserDto userDto);
}
