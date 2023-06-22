package poc.oauth.configs;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static java.time.Duration.ofMinutes;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

  @Value("${app.key.private}")
  private RSAPrivateKey privateKey;
  @Value("${app.key.public}")
  private RSAPublicKey  publicKey;

//  private static final KeyPair keyPair = generateRsaKey();

  @Bean
  SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(
            auth -> auth.requestMatchers(GET, "/demo").hasAuthority("GET_DEMO")
                        .requestMatchers(POST, "/demo").hasAuthority("POST_DEMO")
                        .anyRequest().authenticated()
        )
        .build();
  }

  @Bean
  @Order(1)
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        .csrf(CsrfConfigurer::disable)
        .cors(withDefaults())
        .authorizeHttpRequests(
            auth -> auth.requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth -> oauth.jwt(withDefaults()))
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
            .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
        )
        .headers(
            headers -> headers.xssProtection(withDefaults())
                              .contentSecurityPolicy(
                                  config -> config.policyDirectives("script-src 'self'")
                              )
        )
        .build();
  }

  @Bean
  public JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    grantedAuthoritiesConverter.setAuthorityPrefix("");
    JwtAuthenticationConverter authConverter = new JwtAuthenticationConverter();
    authConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
    return authConverter;
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    config.addAllowedOrigin("*");
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    config.setMaxAge(ofMinutes(30));
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  @Bean
  JwtDecoder jwtDecoder() {
//    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
//    OAuth2TokenValidator<Jwt> withClockSkew =
//        new DelegatingOAuth2TokenValidator<>(
//            new JwtTimestampValidator(Duration.ofSeconds(0)));
//    jwtDecoder.setJwtValidator(withClockSkew);
    return jwtDecoder;
  }

  @Bean
  JwtEncoder jwtEncoder() {
//    var publicKey  = (RSAPublicKey) keyPair.getPublic();
//    var privateKey = (RSAPrivateKey) keyPair.getPrivate();
    var rsaKey    = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
    var jwkSet    = new JWKSet(rsaKey);
    var jwkSource = new ImmutableJWKSet<>(jwkSet);
    return new NimbusJwtEncoder(jwkSource);
  }

//  private static KeyPair generateRsaKey() {
//    KeyPair keyPair;
//    try {
//      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//      keyPairGenerator.initialize(2048);
//      keyPair = keyPairGenerator.generateKeyPair();
//    } catch (Exception ex) {
//      throw new IllegalStateException(ex);
//    }
//    return keyPair;
//  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  UserDetailsService userDetailsService() {
    String pass = passwordEncoder().encode("1234");
    return new InMemoryUserDetailsManager(
        User.withUsername("admin")
            .password(pass)
            .authorities("GET_DEMO", "POST_DEMO")
            .build(),
        User.withUsername("user")
            .password(pass)
            .authorities("GET_DEMO")
            .build()
    );
  }
}
