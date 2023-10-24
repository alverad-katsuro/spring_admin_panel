package br.com.alverad.admin_panel.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Component
public class RequestMatcherBuilder {
    private final HandlerMappingIntrospector introspector;
    private final String servletPath;

    @Autowired
    public RequestMatcherBuilder(HandlerMappingIntrospector introspector) {
        this(introspector, null);
    }

    private RequestMatcherBuilder(HandlerMappingIntrospector introspector, String servletPath) {
        this.introspector = introspector;
        this.servletPath = servletPath;
    }

    public MvcRequestMatcher[] matchers(String... patterns) {
        MvcRequestMatcher[] matchers = new MvcRequestMatcher[patterns.length];
        for (int index = 0; index < patterns.length; index++) {
            matchers[index] = new MvcRequestMatcher(this.introspector, patterns[index]);
            if (this.servletPath != null) {
                matchers[index].setServletPath(this.servletPath);
            }
        }
        return matchers;
    }

    public MvcRequestMatcher[] matchers(HttpMethod method, String... patterns) {
        MvcRequestMatcher[] matchers = new MvcRequestMatcher[patterns.length];
        for (int index = 0; index < patterns.length; index++) {
            matchers[index] = new MvcRequestMatcher(this.introspector, patterns[index]);
            matchers[index].setMethod(method);
            if (this.servletPath != null) {
                matchers[index].setServletPath(this.servletPath);
            }
        }
        return matchers;
    }

    public RequestMatcherBuilder servletPath(String path) {
        return new RequestMatcherBuilder(this.introspector, path);
    }
}