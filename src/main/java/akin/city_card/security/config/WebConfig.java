package akin.city_card.security.config;

import akin.city_card.contract.interceptor.MandatoryContractInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final MandatoryContractInterceptor mandatoryContractInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(mandatoryContractInterceptor)
                .addPathPatterns("/v1/api/**")
                .excludePathPatterns(
                        "/v1/api/auth/**",
                        "/v1/api/contract/contracts/**",
                        "/actuator/**",
                        "/swagger-ui/**",
                        "/v3/api-docs/**"
                );
    }
}