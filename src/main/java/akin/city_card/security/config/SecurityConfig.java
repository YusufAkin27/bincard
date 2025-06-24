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
                // Authentication işlemleri
                "/v1/api/auth/login/**",              // login
                "/v1/api/user/sign-up/**",            // kullanıcı kayıt
                "/v1/api/user/collective-sign-up/**", // toplu kayıt
                "/v1/api/user/verify/phone/**",       // telefon doğrulama
                "/v1/api/user/verify/email/**",       // email doğrulama (hem GET hem POST olabilir)
                "/v1/api/user/verify/email/send",
                "/v1/api/user/verify/phone/resend/**",// email doğrulama linki gönderme
                "/v1/api/user/password/forgot/**",    // şifre sıfırlama kodu gönderme
                "/v1/api/user/password/reset/**",
                "/v1/api/admin/sign-up",
                "/v1/api/user/password/verify-code",
                "/v1/api/auth/phone-verify",
                "/v1/api/user/password/reset",

                "/v1/api/user/active/**",              // aktif etme işlemleri varsa
                // Diğer izin verilenler (örnek: token yenileme)
                "/v1/api/token/**",
                // Admin kayıt yolu
                "/v1/api/admin/register"
        };


        // Sadece admin için yollar
        String[] adminPaths = {
                "/v1/api/admin/**"
        };

        // Öğrenci rolleri için yollar
        String[] userPaths = {
                "/v1/api/user/**"
        };

        return httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // CORS yapılandırmasını ekledik
                .csrf(AbstractHttpConfigurer::disable) // CSRF'yi devre dışı bırak
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless yapı
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
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

        // Flutter emülatörleri ve tarayıcıdan gelen istekler için izin verilen origin'ler
        configuration.setAllowedOrigins(List.of(
                "http://localhost:3000",     // Web uygulamaları için
                "http://127.0.0.1:3000",     // Alternatif localhost
                "http://10.0.2.2:3000",      // Android emülatörü (localhost yönlendirmesi)
                "http://10.0.3.2:3000"       // Genymotion emülatörü (bazı durumlarda)
        ));

        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


}