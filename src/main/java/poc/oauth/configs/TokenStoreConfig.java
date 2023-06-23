package poc.oauth.configs;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class TokenStoreConfig {

  private static final RSAPrivateKey privateKey;
  private static final RSAPublicKey  publicKey;

  static {
    var keyPair = generateRsaKey();
    publicKey  = (RSAPublicKey) keyPair.getPublic();
    privateKey = (RSAPrivateKey) keyPair.getPrivate();
  }

  @Bean
  JwtDecoder jwtDecoder() {
//    OAuth2TokenValidator<Jwt> withClockSkew =
//        new DelegatingOAuth2TokenValidator<>(
//            new JwtTimestampValidator(Duration.ofSeconds(0)));
//    jwtDecoder.setJwtValidator(withClockSkew);
    return NimbusJwtDecoder.withPublicKey(publicKey).build();
  }

  @Bean
  JwtEncoder jwtEncoder() {
    var rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
    var jwkSet = new JWKSet(rsaKey);
    var jwks   = new ImmutableJWKSet<>(jwkSet);
    return new NimbusJwtEncoder(jwks);
  }

  private static KeyPair generateRsaKey() {
    try {
      var generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      return generator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }
}
