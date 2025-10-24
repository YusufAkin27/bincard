package akin.city_card.contract.interceptor;

import akin.city_card.contract.model.Contract;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.config.SecurityConfig;
import akin.city_card.security.entity.Role;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class MandatoryContractInterceptor implements HandlerInterceptor {

    private final ContractService contractService;
    private final ObjectMapper objectMapper;

    private final List<String> excludedPaths = List.of(SecurityConfig.publicPaths);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestPath = request.getRequestURI();

        // Excluded path'leri kontrol et
        if (isExcludedPath(requestPath)) {
            return true;
        }

        // Authentication kontrolü
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                "anonymousUser".equals(authentication.getPrincipal())) {
            return true; // Giriş yapmamış kullanıcılar için kontrol yapma
        }

        // SUPERADMIN rolü kontrolü - SUPERADMIN'ler sözleşme kontrolünden muaf
        if (hasAdminOrSuperAdminRole(authentication)) {
            log.debug("SUPERADMIN kullanıcısı {} sözleşme kontrolünden muaf tutuldu", authentication.getName());
            return true;
        }

        String username = authentication.getName();

        try {
            // Kullanıcının tüm zorunlu sözleşmeleri onaylayıp onaylamadığını kontrol et
            boolean hasAcceptedAllMandatory = contractService.hasUserAcceptedAllMandatoryContracts(username);

            if (!hasAcceptedAllMandatory) {
                // Onaylanmamış zorunlu sözleşmeleri al
                List<Contract> unacceptedContracts = contractService.getUnacceptedMandatoryContracts(username);

                log.warn("Kullanıcı {} zorunlu sözleşmeleri onaylamamış. Onaylanmamış sözleşme sayısı: {}",
                        username, unacceptedContracts.size());

                // HTTP 423 (Locked) response döndür
                response.setStatus(HttpStatus.LOCKED.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("UTF-8");

                ResponseMessage errorResponse = new ResponseMessage(
                        "Devam etmek için önce zorunlu sözleşmeleri onaylamanız gerekmektedir. " +
                                "Lütfen /v1/api/contract/contracts endpoint'ini kullanarak sözleşmeleri görüntüleyin ve onaylayın.",
                        false
                );

                String jsonResponse = objectMapper.writeValueAsString(errorResponse);
                response.getWriter().write(jsonResponse);
                response.getWriter().flush();

                return false;
            }

            return true;

        } catch (Exception e) {
            log.error("Zorunlu sözleşme kontrolü sırasında hata oluştu: ", e);
            // Hata durumunda kullanıcının devam etmesine izin ver
            return true;
        }
    }

    private boolean isExcludedPath(String requestPath) {
        return excludedPaths.stream().anyMatch(requestPath::startsWith);
    }


    private boolean hasAdminOrSuperAdminRole(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority ->
                        Role.SUPERADMIN.getAuthority().equals(authority) ||
                                Role.ADMIN_ALL.getAuthority().equals(authority)
                                ||  Role.CONTRACT_ADMIN.getAuthority().equals(authority)
                );
    }

}