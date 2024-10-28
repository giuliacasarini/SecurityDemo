
- [Chapter IV: Advanced Security Techniques in Spring Boot Applications](#chapter-iv-advanced-security-techniques-in-spring-boot-applications)
    * [Introduction](#introduction)
    * [Setting Up the Project ](#1-setting-up-the-project)
    * [JWT version](#2-jwt-version)
    * [HTTP version](#3-http-version)

    
# Chapter IV: Advanced Security Techniques in Spring Boot Applications
## Introduction

In this final chapter, we will explore the development of a Spring Boot application that handles user registration, login, and logout functionalities. This application will leverage key security concepts such as password encryption, Time-based One-Time Password (TOTP) for login, and JSON Web Tokens (JWT) for managing user sessions. By the end of this chapter, you will have a comprehensive understanding of how to implement robust security measures in a Spring Boot application.  

## Practical Implementation  

## 1. Setting Up the Project  
Start by creating a new Spring Boot project using Spring Initializr. <br> Include dependencies for Spring Web, Spring Security, Spring Data JPA, and JWT.  

**Focus technologies:**

* **Password Encryption**: Implement password encryption using BCrypt. This ensures that user passwords are securely stored in the database.  
* **TOTP for Login**: Integrate TOTP for an additional layer of security during login. Use libraries like Google Authenticator or similar to generate and validate TOTP codes.  
* **JWT for User Sessions**: Use JWT to manage user sessions. Implement a filter to validate JWT tokens with each request

## 2. JWT version

### 2.1 Project Structure

Security\_Demo  
└── src  
    └── main  
        └── java  
            └── Security\_Demo  
                ├── config  
                │   ├── CustomAuthenticationFilter  
                │   ├── CustomAuthenticationProvider  
                │   ├── CustomAuthenticationSuccessHandler  
                │   ├── CustomAuthenticationToken  
                │   ├── CustomUserDetails  
                │   ├── JwtAuthenticationFilter  
                │   └── SecurityConfig  
                ├── controller  
                │   └── UserController  
                ├── dto  
                │   ├── ChangePasswordRequest  
                │   └── UserDto  
                ├── entity  
                │   └── User  
                ├── repository  
                │   └── UserRepository  
                ├── service  
                │   ├── CustomUserDetailsService  
                │   ├── JwtService  
                │   ├── OTPService  
                │   ├── UserService  
                │   └── UserServiceImpl  
                └── SecurityDemoApplication

### 2.2 Detailed File Analysis <br>
**Package config**: Contains the classes that configure the security system and handle various authentication filters.

Let's have a look at each class inside the `config` package:

* **CustomAuthenticationFilter**: This filter intercepts custom authentication requests:
    - totpcode is the form input related to the otp code that is passed to the obtain otp code function 
    - the otp code is passed along with the username and password to the CustomAuthenticationToken function

	
```java
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    public static final String SPRING_SECURITY_FORM_TOTP_CODE = "totpcode";

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        CustomAuthenticationToken authRequest = getAuthRequest(request);
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    private CustomAuthenticationToken getAuthRequest(HttpServletRequest request) {
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        Integer otpCode = Integer.parseInt(obtainOtpCode(request));

        return new CustomAuthenticationToken(username, password, otpCode);
    }

    private String obtainOtpCode(HttpServletRequest request) {
        return request.getParameter(SPRING_SECURITY_FORM_TOTP_CODE);
    }
}
```
* **CustomAuthenticationProvider**: Manages custom authentication, likely with specific validations for this project.  
   - The authentication process begins by searching for the user in the database using the username, checking if the password matches the one stored in the database, and verifying if the OTP code is valid with respect to the key stored in the database. If everything is correct, the authentication is successfully completed
 
```java    
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
``` 
* **CustomAuthenticationSuccessHandler**: Defines what happens when authentication is successful.  
  - successHandler handles what needs to happen: 
    - If authentication is successful: generates the jwt token for the newly authenticated user and saves it in a cookie that is attached to the response sent to the client. Then the response saves the cookie and redirects the user to the home page.  
    - If authentication is not successful, it will log the failure reason and redirect the user back to the login page with an error parameter.
```java    
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
  
 ```   
* **CustomAuthenticationToken**: Represents a custom authentication token used to identify users.  
    - Add otp code to the standard authentication parameters as well.  
  
    
```java
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
```   
* **CustomUserDetails**: Implements custom user details for the authentication process.  
    -  Adds to the standard parameters authkey: the key saved in the db to generate otp codes.


```java
public class CustomUserDetails implements UserDetails {
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private String fullname;
    private String authkey;

    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities,
                             String fullname, String authkey) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.fullname = fullname;
        this.authkey = authkey;
    }

    public String getFullname() {
        return fullname;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public String getAuthkey() {
        return authkey;
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

* **JwtAuthenticationFilter**: A filter that checks the validity of the JWT token in requests.  
    - When a new request comes in, it goes to check if there is a cookie that contains a jwt token. If so, it checks that the token is valid and if it is, the user is authenticated automatically  

```java  
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final HandlerExceptionResolver handlerExceptionResolver;

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            UserDetailsService userDetailsService,
            HandlerExceptionResolver handlerExceptionResolver
    ) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            filterChain.doFilter(request, response);
            System.out.println("NO JWT TOKEN");
            return;
        }


        try {
            for (Cookie cookie : cookies) {
                if ("jwtToken".equals(cookie.getName())) {
                    System.out.println("JWT TOKEN PRESENT");
                    String jwtToken = cookie.getValue();
                    final String username = jwtService.extractUsername(jwtToken);

                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                    if (username != null && authentication == null) {
                        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                        if (jwtService.isTokenValid(jwtToken, userDetails)) {
                            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authToken);
                        }
                    }

                    filterChain.doFilter(request, response);
                }
                 }
        } catch (Exception exception) {
            handlerExceptionResolver.resolveException(request, response, null, exception);
        }
    }
}
```

* **SecurityConfig**: Contains the main Spring Security configuration for the project, such as enabling filters and managing secure routes.
    - In the securityfilterchain the session is stateless → no http sessions are used.  
    - Provider is passed to do authentication: register and login can be accessed without authentication, to access the rest the user must be authenticated.  
With addfilterbefore filters are added for authentication and jwt token verification so that the check is done before authentication

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final OTPService otpService;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtService jwtService;
    @Autowired
    public SecurityConfig(CustomUserDetailsService customUserDetailsService, AuthenticationConfiguration authenticationConfiguration, OTPService otpService, JwtAuthenticationFilter jwtAuthenticationFilter, JwtService jwtService) {
        this.customUserDetailsService = customUserDetailsService;
        this.authenticationConfiguration = authenticationConfiguration;
        this.otpService = otpService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtService = jwtService;
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CustomAuthenticationFilter authenticationFilter(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        CustomAuthenticationFilter filter = new CustomAuthenticationFilter(authenticationConfiguration.getAuthenticationManager());
        filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"));
        filter.setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler(jwtService, customUserDetailsService));
        filter.setSecurityContextRepository(new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(),
                new HttpSessionSecurityContextRepository()
        ));
        return filter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .addFilter(authenticationFilter(authenticationConfiguration))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(new CustomAuthenticationProvider(customUserDetailsService, passwordEncoder(), otpService))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );


        return http.build();
    }
}
```
**Package controller**: Manages HTTP requests and handles the presentation logic.

* **UserController**: Explain that this class handles user requests such as login, registration, and password management. It orchestrates these operations by using the appropriate services.

```java
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
        if (Objects.equals(changePasswordRequest.getNewPassword(), changePasswordRequest.getConfirmPassword())){
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

```
**Package dto**: Defines data structures used to transport information between the client and server.

* **ChangePasswordRequest**: This object represents the data required for a password change request.  
```java    
  public class ChangePasswordRequest {  
      private String oldPassword;  
      private String newPassword;  
      private String confirmPassword;  
  }  
```  
* **UserDto**:it Represents an object that contains essential user information and it is used for user’s registration.
```java    
  public class UserDto {   
      private String username;  
      private String password;  
      private String fullname;     
  }
```
**Package entity**: Contains entities that represent persistent objects (in the database).

* **User**: This class represents the user model, likely including attributes such as `id`, `username`, `password`, and other data related to authentication and user profiles.
```java
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
```
**Package repository**: Handles data persistence and database management.

* **UserRepository**: It is the interface that extends JpaRepository, used for CRUD (Create, Read, Update, Delete) operations on users. Explain how JpaRepository works and how it is used to access the database.
```java
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    User save(UserDto userDto);
}
```
**Package service**: Contains business logic related to user authentication and management.

* **CustomUserDetailsService**: This class implements the logic for loading users for JWT-based authentication. It returns the user's parameters 
 
```java    

public class CustomUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;
    public CustomUserDetailsService(UserRepository userRepository) {
        super();
        this.userRepository = userRepository;
    }

    @Override
    public CustomUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("Username or Password not found");
        }
        return new CustomUserDetails(user.getUsername(), user.getPassword(), authorities(), user.getFullname(), user.getAuthkey());
    }

    public Collection<? extends GrantedAuthority> authorities() {
        return Arrays.asList(new SimpleGrantedAuthority("USER"));
    }

}  
```    
* **JwtService**: Manages the creation and validation of JWT tokens.   
    
```java    
public class JwtService {
    @Value("${security.jwt.secret-key}")
    private String secretKey;
    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;
    public String extractUsername(String token) {
        Claims claims = extractClaim(token);
        return claims.getSubject();
    }

    public Claims extractClaim(String token) {
        final Claims claims = extractAllClaims(token);
        return claims;
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        Claims claims = extractClaim(token);
        return claims.getExpiration();
    }


    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

```    
* **OTPService**: Handles the management of OTPs, which can be useful for a second level of authentication.  

```java    
public class OTPService {
    private static final String ISSUER = "Security Demo";

    // Generate a new TOTP key
    public String generateKey() {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        final GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    // Validate the TOTP code
    public boolean isValid(String secret, int code) {
        GoogleAuthenticator gAuth = new GoogleAuthenticator(
                new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder().build()
        );
        return gAuth.authorize(secret, code);
    }

    // Generate a QR code URL for Google Authenticator
    public String generateQRUrl(String secret, String username) {
        String url = GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(
                ISSUER,
                username,
                new GoogleAuthenticatorKey.Builder(secret).build());
        try {
            return generateQRBase64(url);
        } catch (Exception e) {
            return null;
        }
    }

    // Generate a QR code image in Base64 format
    public static String generateQRBase64(String qrCodeText) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            Map<EncodeHintType, Object> hintMap = new HashMap<>();
            hintMap.put(EncodeHintType.CHARACTER_SET, "UTF-8");

            BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeText, BarcodeFormat.QR_CODE, 200, 200, hintMap);
            BufferedImage bufferedImage = MatrixToImageWriter.toBufferedImage(bitMatrix);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(bufferedImage, "png", baos);
            byte[] imageBytes = baos.toByteArray();
            return Base64.getEncoder().encodeToString(imageBytes);
        } catch (WriterException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
  
```    
* **UserService**: The user service interface, defining available operations.
```java
public interface UserService {  
    User findByUsername(String username);  
    User save(UserDto userDto, String authkey);  
    void changePassword(String username, ChangePasswordRequest changePasswordRequest);  
}
```
* **UserServiceImpl**: The implementation of the user service, handling business logic like user registration and credential management.
    - return a user
    - save a user
    - change user pwd

```java
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
```
## 3. HTTP version


### 3.1 Project Structure

Security\_Demo  
└── src  
    └── main  
        └── java  
            └── Security\_Demo  
                ├── config  
                │   ├── CustomAuthenticationFilter  
                │   ├── CustomAuthenticationProvider  
                │   ├── CustomAuthenticationSuccessHandler  
                │   ├── CustomAuthenticationToken  
                │   ├── CustomUserDetails  
                │   └── SecurityConfig  
                ├── controller  
                │   └── UserController  
                ├── dto  
                │   ├── ChangePasswordRequest  
                │   └── UserDto  
                ├── entity  
                │   └── User  
                ├── repository  
                │   └── UserRepository  
                ├── service  
                │   ├── CustomUserDetailsService  
                │   ├── OTPService  
                │   ├── UserService  
                │   └── UserServiceImpl  
                └── SecurityDemoApplication

### 3.2 Detailed File Analysis <br>
**Package config**
* **CustomAuthenticationSuccessHandler**:
 defines a custom authentication success handler that, upon successful user login, logs the username to the console and redirects the user to the home page.
```java
public class CustomAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        System.out.println("Logged user: " + authentication.getName());

        response.sendRedirect("/home");
    }
}
```
* **SecurityConfig**:It configures Spring Security settings, including custom authentication handling, password encoding, request authorization, and logout management.
```java
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final OTPService otpService;
    
    @Autowired
    public SecurityConfig(CustomUserDetailsService customUserDetailsService, AuthenticationConfiguration authenticationConfiguration, OTPService otpService) {
        this.customUserDetailsService = customUserDetailsService;
        this.authenticationConfiguration = authenticationConfiguration;
        this.otpService = otpService;
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CustomAuthenticationFilter authenticationFilter(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        CustomAuthenticationFilter filter = new CustomAuthenticationFilter(authenticationConfiguration.getAuthenticationManager());
        filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"));
        filter.setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler());
        filter.setSecurityContextRepository(new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(),
                new HttpSessionSecurityContextRepository()
        ));
        return filter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .addFilter(authenticationFilter(authenticationConfiguration))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                .authenticationProvider(new CustomAuthenticationProvider(customUserDetailsService, passwordEncoder(), otpService))
                .logout(logout -> logout
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );

        return http.build();
    }
}
  
```

### Conclusion
This chapter explored advanced security techniques implemented in a Spring Boot application, integrating critical functionalities such as user registration, login, and session management. By utilizing password encryption with BCrypt, two-factor authentication through TOTP, and JSON Web Token (JWT)-based sessions, a robust and secure architecture for handling user authentication was developed.

The practical implementation provided insights into configuring and managing key components of Spring Security, setting up filters, and handling authentication in a customized manner to suit complex scenarios. 