package akin.city_card.security.config;

import akin.city_card.security.entity.Role;
import akin.city_card.security.filter.IpWhitelistFilter;
import akin.city_card.security.filter.JwtAuthenticationFilter;
import akin.city_card.security.filter.RateLimitFilter;
import akin.city_card.security.filter.SecurityEnhancementFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RateLimitFilter rateLimitFilter;
    private final IpWhitelistFilter ipWhitelistFilter;
    private final SecurityEnhancementFilter securityEnhancementFilter;
    public static String[] publicPaths = {
            "/v1/api/user/sign-up/**",
            "/v1/api/buscard/**",
            "/v1/api/user/collective-sign-up/**",
            "/v1/api/user/verify/phone/**",
            "/v1/api/user/verify/email/**",
            "/v1/api/user/verify/email/send",
            "/v1/api/user/verify/phone/resend/**",
            "/v1/api/user/password/forgot/**",
            "/v1/api/user/password/reset/**",
            "/v1/api/user/password/verify-code",
            "/v1/api/user/password/reset",
            "/v1/api/auth/**",
            "/v1/api/user/active/**",
            "/v1/api/token/**",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/v1/api/payment-point",
            "/v1/api/payment-point/search",
            "/v1/api/payment-point/nearby",
            "/v1/api/payment-point/by-city/**",
            "/v1/api/payment-point/by-payment-method",
            "/v1/api/wallet/payment/3d-callback",
            "/v1/api/payment-point/*",
            "/v1/api/payment-point/*/photos",
            "/v1/api/payment-point/*/photos/*",
            "/v1/api/payment-point/*/status",
            "/v1/api/user/email-verify/**",
            "/v1/api/wallet/name/**",
            "/v1/api/public/contracts/**",
            "/v1/api/news/**",
            "/v1/api/tracking/**",
            "/v1/api/simulation/**",
            "/v1/api/feedback/**",
            "/v1/api/bus/**",
            "/v1/api/station/**",
            "/v1/api/route/**"
    };

    // Admin için IP kontrolü gerektiren yollar
    static String[] adminPaths = {
            "/v1/api/admin/**",
            "/v1/api/admin/users/**",
            "/v1/api/payment-point", // POST yeni ekleme
            "/v1/api/payment-point/*/status", // PATCH: Tek seviye (id/status)
            "/v1/api/payment-point/*/photos", // POST: Fotoğraf ekleme
            "/v1/api/feedback/statistics/**",
            "/v1/api/payment-point/*/photos/*", // DELETE: Fotoğraf silme
            "/v1/api/payment-point/*", // PUT & DELETE: Güncelleme ve silme
    };

    // SuperAdmin için IP kontrolü gerektiren yollar
    static String[] superAdminPaths = {
            "/v1/api/super-admin/**",
            "/v1/api/health/**",
            "/v1/api/admin/users/**"
    };

    // Kullanıcı yolları
    static String[] userPaths = {
            "/v1/api/user/**",
            "/api/notifications/**",
    };

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {


        return httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Security Headers
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .contentTypeOptions(withDefaults -> {
                        }) // No-op to enable it
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .preload(true)
                                .maxAgeInSeconds(31536000))
                        .addHeaderWriter(new XContentTypeOptionsHeaderWriter())
                        .addHeaderWriter(new XXssProtectionHeaderWriter())
                        .addHeaderWriter(new ReferrerPolicyHeaderWriter(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .addHeaderWriter((request, response) -> {
                            // Modern Permissions Policy header
                            response.setHeader("Permissions-Policy", "geolocation=(self), microphone=(), camera=()");
                        })
                )

                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers(publicPaths).permitAll()
                        .requestMatchers(adminPaths).hasAuthority(Role.ADMIN.getAuthority())
                        .requestMatchers(superAdminPaths).hasAuthority(Role.SUPERADMIN.getAuthority())
                        .requestMatchers(userPaths).hasAuthority(Role.USER.getAuthority())
                        .anyRequest().authenticated()
                )

                // Filter sıralaması kritik
                .addFilterBefore(securityEnhancementFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(ipWhitelistFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Daha güçlü hashing
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOriginPattern("*");

        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-Client-Version",
                "X-Device-ID",
                "X-Platform"
        ));
        configuration.setExposedHeaders(List.of("X-Rate-Limit-Remaining", "X-Rate-Limit-Reset"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}