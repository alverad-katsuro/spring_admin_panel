package br.com.alverad.admin_panel.config.security;

import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.alverad.admin_panel.dto.UsuarioDTO;

@Service
public class CustomOidcUserService extends OidcUserService {

    @Autowired
    private ObjectMapper objectMapper;

    public static final Logger logger = LoggerFactory.getLogger(CustomOidcUserService.class);

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        final OidcUser oidcUser = super.loadUser(userRequest);

        try {
            return getUsuarioDTO(userRequest, oidcUser);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the
            // OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    @SuppressWarnings("unchecked")
    private UsuarioDTO getUsuarioDTO(OidcUserRequest request, OidcUser oidcUser) {
        Decoder decoder = Base64.getUrlDecoder();
        String[] token = request.getAccessToken().getTokenValue().split("\\.");
        Map<String, Object> atributos;
        try {
            atributos = objectMapper.readValue(new String(decoder.decode(token[1])),
                    new TypeReference<Map<String, Object>>() {
                    });
            if (atributos.get("realm_access") instanceof Map<?, ?> realms
                    && realms.get("roles") instanceof List<?> rolesObject) {
                UsuarioDTO usuario = new UsuarioDTO();
                List<SimpleGrantedAuthority> authoritys;
                authoritys = ((List<String>) rolesObject).stream().map(SimpleGrantedAuthority::new).toList();
                usuario.setAuthorities(authoritys);
                usuario.setClaims(oidcUser.getClaims());
                usuario.setOidcIdToken(oidcUser.getIdToken());
                return usuario;
            }
        } catch (JsonProcessingException ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
        return null;
    }
}