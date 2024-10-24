package com.securitydemo.Security_Demo.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String username;
    private String password;
    private String fullname;

    private String authkey;

    public User(String username, String password, String fullname, String authkey) {
        super();
        this.username = username;
        this.password = password;
        this.fullname = fullname;
        this.authkey = authkey;
    }

}
