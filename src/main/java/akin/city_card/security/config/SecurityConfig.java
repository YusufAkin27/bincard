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

    /* ---------------------- PUBLIC ENDPOINTS ---------------------- */
    public static final String[] publicPaths = {
            "/v1/api/user/sign-up/**",
            "/v1/api/admin/sign-up",
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
            "/v1/api/public/contracts/**",
            "/v1/api/news/**",
            "/v1/api/tracking/**",
            "/v1/api/simulation/**",
            "/v1/api/feedback/**",
            "/v1/api/bus/**",
            "/v1/api/station/**",
            "/v1/api/route/**",
            "/v1/api/buscard/**",
            "/v1/api/wallet/payment/3d-callback",
            "/v1/api/payment-point",
            "/v1/api/payment-point/search",
            "/v1/api/payment-point/nearby",
            "/v1/api/payment-point/by-city/**",
            "/v1/api/payment-point/by-payment-method",
            "/v1/api/payment-point/*/photos",
            "/v1/api/payment-point/*/photos/*",
            "/v1/api/payment-point/*/status",
            "/v1/api/user/email-verify/**",
            "/v1/api/wallet/name/**",
            "/swagger-ui/**",
            "/v3/api-docs/**"
    };

    /* ---------------------- USER ENDPOINTS ---------------------- */
    private static final String[] userPaths = {
            "/v1/api/user/**",
            "/api/notifications/**",
            "/v1/api/wallet/**",
            "/v1/api/wallet/payment/**",
            "/v1/api/wallet/transactions/**"
    };

    /* ---------------------- WALLET ADMIN ENDPOINTS ---------------------- */
    private static final String[] walletAdminPaths = {
            "/v1/api/wallet/admin/**",
            "/v1/api/wallet/statistics/**",
            "/v1/api/wallet/report/**"
    };

    /* ---------------------- PAYMENT POINT ADMIN ENDPOINTS ---------------------- */
    private static final String[] paymentPointAdminPaths = {
            "/v1/api/payment-point/**",
            "/v1/api/feedback/statistics/**"
    };

    /* ---------------------- BUS ADMIN ENDPOINTS ---------------------- */
    private static final String[] busAdminPaths = {
            "/v1/api/bus/admin/**",
            "/v1/api/route/admin/**",
            "/v1/api/station/admin/**",
            "/v1/api/buscard/admin/**"
    };

    /* ---------------------- USER ADMIN ENDPOINTS ---------------------- */
    private static final String[] userAdminPaths = {
            "/v1/api/admin/users/**",
            "/v1/api/admin/roles/**"
    };

    /* ---------------------- SUPER ADMIN ENDPOINTS ---------------------- */
    private static final String[] superAdminPaths = {
            "/v1/api/super-admin/**",
            "/v1/api/health/**"
    };

    /* ---------------------- ROLLERİN GRUPLARI ---------------------- */
    private static final String[] allAdminRoles = {
            Role.SUPERADMIN.getAuthority(),
            Role.ADMIN_ALL.getAuthority()
    };

    private static final String[] walletAdminRoles = {
            Role.SUPERADMIN.getAuthority(),
            Role.ADMIN_ALL.getAuthority(),
            Role.WALLET_ADMIN.getAuthority()
    };

    private static final String[] paymentPointAdminRoles = {
            Role.SUPERADMIN.getAuthority(),
            Role.ADMIN_ALL.getAuthority(),
            Role.PAYMENT_POINT_ADMIN.getAuthority()
    };

    private static final String[] busAdminRoles = {
            Role.SUPERADMIN.getAuthority(),
            Role.ADMIN_ALL.getAuthority(),
            Role.BUS_ADMIN.getAuthority(),
            Role.ROUTE_ADMIN.getAuthority(),
            Role.STATION_ADMIN.getAuthority(),
            Role.BUS_CARD_ADMIN.getAuthority()
    };

    private static final String[] userAdminRoles = {
            Role.SUPERADMIN.getAuthority(),
            Role.ADMIN_ALL.getAuthority(),
            Role.USER_ADMIN.getAuthority()
    };

    private static final String[] userRoles = {
            Role.USER.getAuthority(),
            Role.SUPERADMIN.getAuthority(),
            Role.ADMIN_ALL.getAuthority(),
            Role.WALLET_ADMIN.getAuthority()
    };

    /* ---------------------- SECURITY CONFIG ---------------------- */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .contentTypeOptions(withDefaults -> {})
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .preload(true)
                                .maxAgeInSeconds(31536000))
                        .addHeaderWriter(new XContentTypeOptionsHeaderWriter())
                        .addHeaderWriter(new XXssProtectionHeaderWriter())
                        .addHeaderWriter(new ReferrerPolicyHeaderWriter(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .addHeaderWriter((request, response) -> {
                            response.setHeader("Permissions-Policy", "geolocation=(self), microphone=(), camera=()");
                        })
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicPaths).permitAll()
                        .requestMatchers(superAdminPaths).hasAnyAuthority(allAdminRoles)
                        .requestMatchers(userAdminPaths).hasAnyAuthority(userAdminRoles)
                        .requestMatchers(walletAdminPaths).hasAnyAuthority(walletAdminRoles)
                        .requestMatchers(paymentPointAdminPaths).hasAnyAuthority(paymentPointAdminRoles)
                        .requestMatchers(busAdminPaths).hasAnyAuthority(busAdminRoles)
                        .requestMatchers(userPaths).hasAnyAuthority(userRoles)
                        .anyRequest().authenticated()
                )
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