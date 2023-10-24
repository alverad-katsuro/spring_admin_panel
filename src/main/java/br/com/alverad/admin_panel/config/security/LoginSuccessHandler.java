package br.com.alverad.admin_panel.config.security;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import br.com.alverad.admin_panel.dto.UsuarioDTO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        final var role = new SimpleGrantedAuthority("ROLE_SPRING_ACTUATOR");
        if (authentication.getPrincipal() instanceof UsuarioDTO usuario && usuario.getAuthorities() != null
                && usuario.getAuthorities().contains(role)) {

            super.onAuthenticationSuccess(request, response, authentication);

        } else {
            response.sendRedirect(request.getContextPath() + "/login?error");
        }

    }

}
