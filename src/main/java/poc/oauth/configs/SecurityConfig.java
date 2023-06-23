package poc.oauth.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static java.time.Duration.ofMinutes;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {


  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    setupDefaultConfiguration(http);
    return http
        .authorizeHttpRequests(
            auth -> auth.requestMatchers(GET, "/demo").hasAuthority("GET_DEMO")
                        .requestMatchers(POST, "/demo").hasAuthority("POST_DEMO")
                        .anyRequest().authenticated()
        )
        .build();
  }

  private void setupDefaultConfiguration(final HttpSecurity http) throws Exception {
    http.csrf(CsrfConfigurer::disable)
        .cors(withDefaults())
        .authorizeHttpRequests(auth -> auth.requestMatchers("/auth/**").permitAll())
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
        );
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
