package br.com.alverad.admin_panel.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "services")
public record RegistrationDefaultProperties(String registrationId) {

}
