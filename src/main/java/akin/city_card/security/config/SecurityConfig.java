package akin.city_card.security.config;


import akin.city_card.security.entity.Role;
import akin.city_card.security.filter.JwtAuthenticationFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;
import java.util.List;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        String[] publicPaths = {
                "/v1/api/user/sign-up/**",
                "/v1/api/user/collective-sign-up/**",
                "/v1/api/user/verify/phone/**",
                "/v1/api/user/verify/email/**",
                "/v1/api/user/verify/email/send",
                "/v1/api/user/verify/phone/resend/**",
                "/v1/api/user/password/forgot/**",
                "/v1/api/user/password/reset/**",
                "/v1/api/user/password/verify-code",
                "/v1/api/user/password/reset",
                "/v1/api/admin/sign-up",
                "/v1/api/admin/register",
                "/v1/api/auth/**",
                "/v1/api/user/active/**",
                "/v1/api/token/**",
                "/swagger-ui/**",
                "/v3/api-docs/**",

                // Ödeme noktası herkese açık görüntüleme uçları
                "/v1/api/payment-point",                         // GET
                "/v1/api/payment-point/search",                  // POST
                "/v1/api/payment-point/nearby",                  // GET
                "/v1/api/payment-point/by-city/**",              // GET
                "/v1/api/payment-point/by-payment-method",       // GET
                "/v1/api/payment-point/*",                       // GET tekil detay (id)
                "/v1/api/payment-point/*/photos",                // GET (varsa)
                "/v1/api/payment-point/*/photos/*",              // GET (varsa)
                "/v1/api/payment-point/*/status"                 // GET (varsa)
        };


        // Sadece admin için yollar
        String[] adminPaths = {
                "/v1/api/admin/**",
                "/v1/api/user/all",
                "/v1/api/payment-point",                     // POST yeni ekleme
                "/v1/api/payment-point/*/status",            // PATCH: Tek seviye (id/status)
                "/v1/api/payment-point/*/photos",            // POST: Fotoğraf ekleme
                "/v1/api/payment-point/*/photos/*",          // DELETE: Fotoğraf silme
                "/v1/api/payment-point/*",                   // PUT & DELETE: Güncelleme ve silme
        };

// Sadece superadmin yetkisi gerektiren yollar
        String[] superAdminPaths = {
                "/v1/api/super-admin/**",
                "/v1/api/user/all"
        };

// Öğrenci (normal kullanıcı) rolleri için yollar
        String[] userPaths = {
                "/v1/api/user/**"
        };

        return httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // CORS yapılandırmasını ekledik
                .csrf(AbstractHttpConfigurer::disable) // CSRF'yi devre dışı bırak
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless yapı
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/v1/api/auth/**").permitAll()
                        .requestMatchers(publicPaths).permitAll()
                        .requestMatchers("/ws/**").permitAll()  // WebSocket için izin ver
                        .requestMatchers(adminPaths).hasAuthority(Role.ADMIN.getAuthority())
                        .requestMatchers(userPaths).hasAuthority(Role.USER.getAuthority())
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOriginPatterns(List.of("*")); // <- Tüm origin'ler
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(false); // <- true ise wildcard kullanılamaz!

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }



}