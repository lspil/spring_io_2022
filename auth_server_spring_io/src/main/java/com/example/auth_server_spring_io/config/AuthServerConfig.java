package com.example.auth_server_spring_io.config;

import com.example.auth_server_spring_io.config.keys.KeyManager;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.util.UUID;

@Configuration
public class AuthServerConfig {

  private final KeyManager keyManager;

  public AuthServerConfig(KeyManager keyManager) {
    this.keyManager = keyManager;
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain securityFilterChainAs(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    return http.formLogin().and().build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient r1 = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client")
        .clientSecret("secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .scope(OidcScopes.OPENID)
        .redirectUri("http://spring.io/auth")
        .build();

    return new InMemoryRegisteredClientRepository(r1);
  }

  @Bean
  public ProviderSettings providerSettings() {
    return ProviderSettings.builder().build();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    JWKSet set = new JWKSet(keyManager.rsaKey());
    return (j, sc) -> j.select(set);
  }
}
