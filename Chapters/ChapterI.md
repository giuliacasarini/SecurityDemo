# Table of contents

- [Chapter I: Encryption in Spring Boot](#chapter-i-encryption-in-spring-boot)
    * [Introduction](#introduction)
    * [Cryptography and Authentication with BCrypt](#cryptography-and-authentication-with-bcrypt)
      + [Practical Implementation](#practical-implementation)
    * [Alternative Password Hashing: PBKDF2](#pbkdf2-based-password-encoding)



# Chapter I: Encryption in Spring Boot

## Introduction

In this chapter, we will explore the implementation of encryption and password security within a Spring Boot application. Encryption is a vital component of application security, safeguarding sensitive data by converting it into unreadable formats for unauthorized users. We will cover fundamental encryption concepts, the Spring Security Crypto module, and practical steps for integrating encryption mechanisms into a Spring Boot project.

## The Fundamentals of Encryption

Encryption transforms <u>plaintext</u> data into <u>ciphertext</u>, making it unintelligible without the appropriate decryption key. There are two primary types of encryption:

* **Symmetric Encryption**: Uses the same key for both encryption and decryption.  
* **Asymmetric Encryption**: Utilizes different keys, one public for encryption and one private for decryption.


### Why Use Encryption?

Encryption is crucial for securing applications by:


- **Protects Sensitive Data**: Safeguards personal and financial information to ensure only authorized users can access it, upholding confidentiality.
- **Ensures Compliance**: Meets industry regulations (e.g., GDPR, HIPAA) by securing personal and sensitive data, helping to avoid legal repercussions.
- **Maintains Data Integrity**: Protects data from tampering during transmission or storage, ensuring it remains accurate and trustworthy.
- **Defends Against Insider Threats**: Adds an extra layer of security to prevent misuse by those with privileged access to data.
- **Minimizes Breach Impact**: Reduces the potential damage from data breaches, making it harder for attackers to exploit sensitive information.
- **Builds Trust**: Demonstrates a strong commitment to data security, strengthening user trust and enhancing the organization’s reputation.

In **Spring Boot applications**, encryption is commonly used to **secure API communications** and **protect sensitive information**, such as passwords and personal data, stored in databases.

## **Cryptography and Authentication with BCrypt**

Cryptography plays a vital role in safeguarding sensitive data like user passwords. The **BCrypt** algorithm, widely used in Spring Security, offers a robust and secure way to manage password hashing. BCrypt is a password hashing function designed to be computationally intensive, thereby resisting brute-force attacks. It incorporates a salt to protect against rainbow table attacks and is adaptive, allowing configuration to become slower as hardware capabilities improve. Due to its robustness, BCrypt is widely used and easily integrates with various frameworks, including Spring Boot.

Spring Boot provides seamless integration with BCrypt through the Spring Security module, enabling developers to easily encode and verify passwords, thereby enhancing application security.

### **Secure Password Storage**

The first line of defense in our authentication system is the secure storage of passwords. Instead of storing passwords as plain text, which is vulnerable to theft, we hash them using `BCryptPasswordEncoder`, provided by Spring Security. BCrypt applies a unique salt to each password and allows us to adjust the computational cost (or work factor), making it more resistant to brute-force attacks.


In Spring Security, a `PasswordEncoder` is essential for securely storing user passwords by encoding (hashing) them before storage.

```java
@Bean  
public PasswordEncoder passwordEncoder() {  
    return new BCryptPasswordEncoder();  
}
```
This `PasswordEncoder` is used whenever a user creates or updates its password, ensuring that the password is stored securely in its hashed form in the database. When a user logs in, the password they provide is hashed again and compared to the stored hash, without ever exposing the plain-text password.

## Practical Implementation

### Setting Up the Environment
To get started, include the following dependency in `pom.xml`:
```xml
<dependencies>  
    <dependency>  
        <groupId>org.springframework.boot</groupId>  
        <artifactId>spring-boot-starter-security<artifactId>  
    </dependency>  
</dependencies>
```

**Encoding Passwords**  
How to encode passwords using BCrypt in a Spring Boot application:
```java 
public class PasswordEncoderUtil {  
    public static void main(String[] args) {  
        // Create a BCryptPasswordEncoder instance
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();  
        
        // Define the raw password to encode
        String rawPassword = "myPassword";  
        
        // Encode the raw password using BCrypt
        String encodedPassword = passwordEncoder.encode(rawPassword);  
        
        // Output the encoded password
        System.out.println("Encoded Password: " + encodedPassword);  
    }
}
```

**Verifying Passwords**  
Spring Security provides the **PasswordEncoder** interface to hash and verify passwords. The widely used **BCryptPasswordEncoder** hashes passwords using the **BCrypt** algorithm, which incorporates a random salt to protect against dictionary attacks.
```java 
public class PasswordVerifier {

    public static void main(String[] args) {

        // Create a BCryptPasswordEncoder instance
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        // Define the raw password to verify
        String rawPassword = "myPassword";

        // Encoded password to compare the raw password against
        String encodedPassword = "$2a$10$adflvdmsdlxkmdwlms"; 

        // Check if the raw password matches the encoded password
        boolean isPasswordMatch = passwordEncoder.matches(rawPassword, encodedPassword);

        // Output whether the password matches
        System.out.println("Password match: " + isPasswordMatch);
    }
}
```

## PBKDF2-Based Password Encoding

Spring also supports **PBKDF2** (Password-Based Key Derivation Function) for password hashing, which uses a deliberately slow hashing process to prevent brute-force attacks:
```java
public class PasswordEncoderUtil {

    public static void main(String[] args) {
        // Create a PBKDF2 Password Encoder 
        Pbkdf2PasswordEncoder encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        
        // Define the raw password to encode
        String rawPassword = "myPassword";
        
        // Encode the raw password
        String hashedPassword = encoder.encode(rawPassword);
        
        // Output the hashed password
        System.out.println("Hashed Password: " + hashedPassword);
    }
}
```
**Storing Encoded Passwords in a Database**  
When storing passwords in a database, always store the encoded version. Here’s an example using Spring Data JPA:
```java
public interface UserRepository extends JpaRepository<User, Long> {  
    User findByUsername(String username);  
}

@Entity  
public class User {  
    @Id  
    @GeneratedValue(strategy = GenerationType.IDENTITY)  
    private Long id;  
    private String username;  
    private String password; // Store the encoded password 
}

```
**Securing REST APIs with BCrypt**  
To secure REST APIs, utilize Spring Security to authenticate users based on their encoded passwords. Here’s a basic configuration:

```java
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // Define a BCryptPasswordEncoder bean for secure password encoding
    @Bean  
    public BCryptPasswordEncoder passwordEncoder() {  
        return new BCryptPasswordEncoder();  
    }

    // Configure HTTP security rules for the application
     @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .httpBasic();
        return http.build();
    }
}
```


### **Best Practices for Password Management**

Secure Password Policies

Implementing secure password policies is essential for protecting user accounts. Recommendations for creating secure passwords include:

* **Length:** Passwords should be at least 12 characters long.  
* **Complexity:** Encourage the use of a mix of uppercase letters, lowercase letters, numbers, and special characters.  
* **Uniqueness:** Users should be advised against reusing passwords across different accounts.
<br>
</br>
# Handling Password Resets
Password reset functionality must be implemented securely to prevent unauthorized access. This typically involves generating a unique token that is sent to the user’s registered email address. Once the user verifies their identity using the token, they can set a new password, which should be hashed and stored securely.<br>
Implementing secure password reset functionality is crucial to protect user accounts from unauthorized access.<br> The example below outlines the basic steps for generating a password reset token, sending it to the user's registered email, and allowing the user to set a new password.

First define an entity class to represent a password reset token with necessary attributes.
```java
@Entity
public class PasswordResetToken {
    private static final int EXPIRATION = 60 * 24;
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String token;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;
    private Date expiryDate;
}

```
Handle the password reset process by sending a reset token to the user's email.
```java
@PostMapping("/user/resetPassword")
public GenericResponse resetPassword(HttpServletRequest request, 
    @RequestParam("email") String userEmail) {
        User user = userService.findUserByEmail(userEmail);
        if (user == null) {
            throw new UserNotFoundException();
        }
        String token = UUID.randomUUID().toString();
        userService.createPasswordResetTokenForUser(user, token);
        mailSender.send(constructResetTokenEmail(getAppUrl(request), token, user));
        return new GenericResponse(
            messages.getMessage("message.resetPasswordEmail", null));
}

```
Create a new password reset token for the specified user and save it in the repository
```java
public void createPasswordResetTokenForUser(User user, String token) {
    PasswordResetToken myToken = new PasswordResetToken(token, user);
    passwordTokenRepository.save(myToken);
}
```
Construct the email containing the reset token for the user and a generic email message with the specified subject and body for the user
```java
private SimpleMailMessage constructResetTokenEmail(
  String contextPath, String token, User user) {
    String url = contextPath + "/user/changePassword?token=" + token;
    String message = messages.getMessage("message.resetPassword", 
      null);
    return constructEmail("Reset Password", message + " \r\n" + url, user);
}

private SimpleMailMessage constructEmail(String subject, String body, 
  User user) {
    SimpleMailMessage email = new SimpleMailMessage();
    email.setSubject(subject);
    email.setText(body);
    email.setTo(user.getEmail());
    email.setFrom(env.getProperty("support.email"));
    return email;
}

```
Class to represent a generic response message, either successful or with an error:
```java
public class GenericResponse {
    private String message;
    private String error;
 
    public GenericResponse(String message) {
        super();
        this.message = message;
    }
 
    public GenericResponse(String message, String error) {
        super();
        this.message = message;
        this.error = error;
    }
}

```
The change password page, validating the provided token
```java
@GetMapping("/user/changePassword")
public String showChangePasswordPage(Locale locale, Model model, 
  @RequestParam("token") String token) {
    String result = securityService.validatePasswordResetToken(token);
    if(result != null) {
        String message = messages.getMessage("auth.message." + result, null, locale);
        return "redirect:/login.html?message=" + message;
    } else {
        model.addAttribute("token", token);
        return "redirect:/updatePassword.html";
    }
}

```
Validate the password reset token, checking for existence and expiration
```java
public String validatePasswordResetToken(String token) {
    final PasswordResetToken passToken = passwordTokenRepository.findByToken(token);

    return !isTokenFound(passToken) ? "invalidToken"
            : isTokenExpired(passToken) ? "expired"
            : null;
}

private boolean isTokenFound(PasswordResetToken passToken) {
    return passToken != null;
}

private boolean isTokenExpired(PasswordResetToken passToken) {
    final Calendar cal = Calendar.getInstance();
    return passToken.getExpiryDate().before(cal.getTime());
}
```
Save the new password for the user after validating the reset token
```java
@PostMapping("/user/savePassword")
public GenericResponse savePassword(@Valid PasswordDto passwordDto) {

    String result = securityUserService.validatePasswordResetToken(passwordDto.getToken());

    if(result != null) {
        return new GenericResponse(messages.getMessage(
            "auth.message." + result, null));
    }

    Optional user = userService.getUserByPasswordResetToken(passwordDto.getToken());
    if(user.isPresent()) {
        userService.changeUserPassword(user.get(), passwordDto.getNewPassword());
        return new GenericResponse(messages.getMessage(
            "message.resetPasswordSuc", null));
    } else {
        return new GenericResponse(messages.getMessage(
            "auth.message.invalid", null));
    }
}

```
Change the user's password and save the updated user information.
```java
public void changeUserPassword(User user, String password) {
    user.setPassword(passwordEncoder.encode(password));
    repository.save(user);
}
```
Data transfer object for handling password-related information during password reset.
```java
public class PasswordDto {

    private String oldPassword;

    private  String token;

    @ValidPassword
    private String newPassword;
}
```
### Conclusion

In summary, using BCrypt for password hashing in Spring Boot applications is a critical step in securing user credentials. By leveraging the strengths of BCrypt, developers can ensure that user passwords are stored securely, significantly reducing the risk of unauthorized access. This chapter laid the groundwork for understanding password security, and the subsequent chapter will delve into Two-Factor Authentication (2FA) as an additional layer of security to further protect user accounts.


