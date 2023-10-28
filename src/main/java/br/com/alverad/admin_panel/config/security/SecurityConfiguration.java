package br.com.alverad.admin_panel.config.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

	private final LoginSuccessHandler loginSuccessHandler;

	private final CustomOidcUserService customOidcUserService;

	@Bean
	public SecurityFilterChain filterChain(AdminServerProperties adminServer, HttpSecurity httpSecurity)
			throws Exception {
		httpSecurity.csrf(AbstractHttpConfigurer::disable)
				.cors(cors -> cors.configurationSource(corsConfigurationSource()))
				.oauth2Login(e -> e.successHandler(loginSuccessHandler)
						.userInfoEndpoint(user -> user
								.oidcUserService(customOidcUserService)))
				.formLogin(e -> e.disable())
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers(HttpMethod.GET,
								"/v3/api-docs/**",
								"/swagger-ui/**",
								"/swagger-ui.html",
								"/login",
								"*/*.js",
								"*/*.css",
								"/**.js",
								"/instances",
								"/")
						.permitAll()
						.requestMatchers(
								adminServer.path("/actuator/info"),
								adminServer.path("/actuator/health"),
								adminServer.path("/login"),
								adminServer.path("/assets/**"))
						.permitAll()
						.requestMatchers("/actuator/**").hasRole("SPRING_ACTUATOR")

						.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2
						.jwt(Customizer.withDefaults()));

		return httpSecurity.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.applyPermitDefaultValues();
		configuration.setAllowedHeaders(Arrays.asList("Authorization", "Requestor-Type", "Content-Type",
				"Access-Control-Allow-Headers", "access-control-allow-origin"));
		configuration.setExposedHeaders(Arrays.asList("X-Get-Header", "Access-Control-Allow-Methods"));
		configuration.setAllowedMethods(
				Arrays.asList("POST", "GET", "PUT", "DELETE", "PATCH"));
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	@SuppressWarnings("unchecked")
	public JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
				jwt -> {
					Object roles = jwt.getClaimAsMap("realm_access").get("roles");
					if (roles instanceof List<?>) {
						List<String> rolesList = (List<String>) roles;
						JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();
						Collection<GrantedAuthority> allAuthorities = scopesConverter.convert(jwt);
						allAuthorities.addAll(
								rolesList.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList());
						return allAuthorities;
					} else {
						return Collections.emptyList();
					}
				});

		return jwtAuthenticationConverter;
	}
}