package akin.city_card.security.filter;

import akin.city_card.security.entity.Role;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.TokenIsExpiredException;
import akin.city_card.security.exception.TokenNotFoundException;
import akin.city_card.security.service.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getServletPath();
        // /auth dışındaki isteklerde JWT kontrolü yapılacak
        if (path.contains("/auth") && !path.contains("/logout")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                if (jwtService.validateAccessToken(token)) {
                    Claims claims = jwtService.getAccessTokenClaims(token);
                    String userNumber = claims.getSubject();

                    Object rolesObj = claims.get("role");

                    Set<Role> roles;

                    if (rolesObj instanceof List<?>) {
                        roles = ((List<?>) rolesObj).stream()
                                .filter(String.class::isInstance)
                                .map(String.class::cast)
                                .map(roleStr -> Role.valueOf(roleStr.toUpperCase()))
                                .collect(Collectors.toSet());
                    } else if (rolesObj instanceof String) {
                        roles = Set.of(Role.valueOf(((String) rolesObj).toUpperCase()));
                    } else {
                        roles = Collections.emptySet();
                    }

                    SecurityUser userDetails = new SecurityUser(userNumber, roles);
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
                filterChain.doFilter(request, response);
            } catch (TokenIsExpiredException e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"" + e.getMessage() + "\"}");
            } catch (TokenNotFoundException e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"" + e.getMessage() + "\"}");
            } catch (Exception e) {
                // Log hatayı konsola yazabiliriz, ya da logger kullanabilirsin
                e.printStackTrace();

                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Sunucu hatası oluştu.\"}");
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
