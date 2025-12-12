package akin.city_card.user.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.Role;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.exception.VerificationCodeStillValidException;
import akin.city_card.user.core.request.CreateUserRequestList;
import akin.city_card.user.core.request.PermanentDeleteRequest;
import akin.city_card.user.core.request.SuspendUserRequest;
import akin.city_card.user.core.request.UnsuspendUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.core.response.Views;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.UserStatus;
import akin.city_card.user.service.abstracts.AdminUserService;
import akin.city_card.wallet.exceptions.AdminOrSuperAdminNotFoundException;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/v1/api/admin/users")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('USER_ADMIN') or hasAuthority('SUPERADMIN')")
public class AdminUserController {

    private final AdminUserService adminUserService;

    private void isAdminOrSuperAdmin(UserDetails userDetails) throws UnauthorizedAccessException {
        if (userDetails == null || userDetails.getAuthorities() == null) {
            throw new UnauthorizedAccessException();
        }

        boolean authorized = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("USER_ADMIN") || role.equals("SUPERADMIN") || role.equals("ADMIN_ALL"));

        if (!authorized) {
            throw new UnauthorizedAccessException();
        }
    }

    // =============== 1. KULLANICI LİSTESİ YÖNETİMİ ===============

    /**
     * Tüm kullanıcıları sayfalama ile listele
     */
    @GetMapping
    // @JsonView(Views.Admin.class) // Geçici olarak kaldırıldı - test için
    public PageDTO<CacheUserDTO> getAllUsers(
            @AuthenticationPrincipal UserDetails userDetails,
            Pageable pageable,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, AdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);
        PageDTO<CacheUserDTO> result = adminUserService.getAllUsers(pageable, userDetails.getUsername(), httpServletRequest);
        // Debug log
        System.out.println("AdminUserController.getAllUsers - Result: " + 
                (result != null ? "PageDTO with " + (result.getContent() != null ? result.getContent().size() : 0) + " items" : "NULL"));
        return result;
    }

    /**
     * Kullanıcı arama ve filtreleme
     */
    @GetMapping("/search")
    @JsonView(Views.Admin.class)
    public PageDTO<CacheUserDTO> searchUsers(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) String query,
            Pageable pageable,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, AdminNotFoundException {

        isAdminOrSuperAdmin(userDetails);

        return adminUserService.searchUsers(query, pageable, userDetails.getUsername(), httpServletRequest);
    }


    /**
     * Kullanıcı hesaplarını toplu olarak pasifleştirme/aktifleştirme
     */
    @PutMapping("/bulk-status-update")
    public ResponseMessage bulkUpdateUserStatus(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody Map<String, Object> request,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        // Integer'ları Long'a dönüştür (JSON'dan gelen sayılar Integer olabilir)
        List<Long> userIds = new ArrayList<>();
        Object userIdsObj = request.get("userIds");
        if (userIdsObj instanceof List) {
            for (Object id : (List<?>) userIdsObj) {
                if (id instanceof Integer) {
                    userIds.add(((Integer) id).longValue());
                } else if (id instanceof Long) {
                    userIds.add((Long) id);
                } else if (id instanceof Number) {
                    userIds.add(((Number) id).longValue());
                } else {
                    userIds.add(Long.parseLong(id.toString()));
                }
            }
        }
        
        UserStatus newStatus = UserStatus.valueOf((String) request.get("status"));

        return adminUserService.bulkUpdateUserStatus(userIds, newStatus, userDetails.getUsername(), httpServletRequest);

    }

    /**
     * Toplu kullanıcı silme
     */
    @DeleteMapping("/bulk-delete")
    public ResponseMessage bulkDeleteUsers(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody List<Long> userIds,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.bulkDeleteUsers(userIds, userDetails.getUsername(), httpServletRequest);
    }

    // =============== 2. KULLANICI DETAYLARI ===============

    /**
     * Belirli kullanıcının detaylı bilgilerini görüntüleme
     */
    @GetMapping("/{userId}")
    public CacheUserDTO getUserDetails(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, UserNotFoundException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserById(userId, userDetails.getUsername(), httpServletRequest);
    }

    /**
     * Kullanıcıya ait cihaz ve IP bilgilerini görüntüleme
     */
    @GetMapping("/{userId}/device-info")
    public Map<String, Object> getUserDeviceInfo(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, UserNotFoundException, AdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserDeviceInfo(userId, userDetails.getUsername(), httpServletRequest);

    }

    // =============== 3. ROL VE YETKİ YÖNETİMİ ===============

    /**
     * Kullanıcıya rol atama
     */
    @PostMapping("/{userId}/roles")
    public ResponseMessage assignRolesToUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestBody Set<Role> roles,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.assignRolesToUser(userId, roles, userDetails.getUsername(), httpServletRequest);

    }

    /**
     * Kullanıcıdan rol kaldırma
     */
    @DeleteMapping("/{userId}/roles")
    public ResponseMessage removeRolesFromUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestBody Set<Role> roles,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.removeRolesFromUser(userId, roles, userDetails.getUsername(), httpServletRequest);

    }

    /**
     * Toplu rol atama
     */
    @PostMapping("/bulk-role-assignment")
    public ResponseMessage bulkAssignRoles(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody Map<String, Object> request,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, UserNotFoundException, AdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        // Integer'ları Long'a dönüştür (JSON'dan gelen sayılar Integer olabilir)
        List<Long> userIds = new ArrayList<>();
        Object userIdsObj = request.get("userIds");
        if (userIdsObj instanceof List) {
            for (Object id : (List<?>) userIdsObj) {
                if (id instanceof Integer) {
                    userIds.add(((Integer) id).longValue());
                } else if (id instanceof Long) {
                    userIds.add((Long) id);
                } else if (id instanceof Number) {
                    userIds.add(((Number) id).longValue());
                } else {
                    userIds.add(Long.parseLong(id.toString()));
                }
            }
        }
        
        // Set.of immutable döndürür, HashSet kullan
        Set<Role> roles = new HashSet<>();
        Object roleObj = request.get("role");
        if (roleObj instanceof String) {
            roles.add(Role.valueOf((String) roleObj));
        } else if (roleObj instanceof List) {
            ((List<?>) roleObj).forEach(r -> roles.add(Role.valueOf(r.toString())));
        }

        return adminUserService.bulkAssignRoles(userIds, roles, userDetails.getUsername(), httpServletRequest);

    }

    // =============== 4. PAROLA VE GÜVENLİK ===============

    /**
     * Admin tarafından kullanıcı parolasını sıfırlama
     */
    @PostMapping("/{userId}/reset-password")
    public ResponseMessage resetUserPassword(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestBody Map<String, String> request,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, UserNotFoundException, AdminNotFoundException {

        isAdminOrSuperAdmin(userDetails);

        String newPassword = request.get("newPassword");
        if (newPassword == null || newPassword.isBlank()) {
            throw new IllegalArgumentException("newPassword alanı boş olamaz");
        }

        return adminUserService.resetUserPassword(userId, newPassword, userDetails.getUsername(), httpServletRequest);
    }


    /**
     * E-posta doğrulama durumu güncelleme
     */
    @PutMapping("/{userId}/email-verification")
    public ResponseMessage updateEmailVerificationStatus(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestBody Map<String, Boolean> request,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, UserNotFoundException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        boolean verified = request.get("verified");
        return adminUserService.updateEmailVerificationStatus(userId, verified, userDetails.getUsername(), httpServletRequest);

    }

    /**
     * Telefon doğrulama durumu güncelleme
     */
    @PutMapping("/{userId}/phone-verification")
    public ResponseMessage updatePhoneVerificationStatus(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long userId,
            @RequestBody Map<String, Boolean> request,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException, UserNotFoundException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        boolean verified = request.get("verified");
        return adminUserService.updatePhoneVerificationStatus(userId, verified, userDetails.getUsername(), httpServletRequest);

    }

    // =============== 6. OTURUM YÖNETİMİ ===============

    /**
     * Kullanıcının aktif oturumlarını listeleme
     */
    @GetMapping("/{userId}/active-sessions")
    public List<Map<String, Object>> getUserActiveSessions(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserActiveSessions(userId, httpServletRequest);
    }

    /**
     * Kullanıcının belirli oturumunu sonlandırma
     */
    @DeleteMapping("/{userId}/sessions/{sessionId}")
    public ResponseMessage terminateUserSession(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @PathVariable("sessionId") String sessionId,
            HttpServletRequest httpServletRequest) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.terminateUserSession(userId, sessionId, userDetails.getUsername(), httpServletRequest);
    }


    /**
     * IP adresini engelleme
     */
    @PostMapping("/ip-ban")
    public ResponseMessage banIpAddress(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody Map<String, Object> request) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        String ipAddress = (String) request.get("ipAddress");
        String reason = (String) request.get("reason");
        LocalDateTime expiresAt = request.containsKey("expiresAt") ?
                LocalDateTime.parse((String) request.get("expiresAt")) : null;

        return adminUserService.banIpAddress(ipAddress, reason, expiresAt, userDetails.getUsername());
    }

    // Kullanıcıyı askıya alma
    @PostMapping("/admin/{userId}/suspend")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'SUPERADMIN')")
    public ResponseMessage suspendUser(
            @PathVariable("userId") Long userId,
            @RequestBody SuspendUserRequest request,
            @AuthenticationPrincipal UserDetails adminDetails
    ) throws UserNotFoundException, UnauthorizedAreaException {
        return adminUserService.suspendUser(adminDetails.getUsername(), userId, request);
    }

    // Kullanıcı hesabını kalıcı olarak silme
    @DeleteMapping("/admin/{userId}/delete")
    @PreAuthorize("hasAuthority('SUPERADMIN')")
    public ResponseMessage permanentlyDeleteUser(
            @PathVariable("userId") Long userId,
            @RequestBody PermanentDeleteRequest request,
            @AuthenticationPrincipal UserDetails adminDetails
    ) throws UserNotFoundException, UnauthorizedAreaException {
        return adminUserService.permanentlyDeleteUser(adminDetails.getUsername(), userId, request);
    }

    // Kullanıcı askıya alma işlemini kaldırma
    @PostMapping("/admin/{userId}/unsuspend")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'SUPERADMIN')")
    public ResponseMessage unsuspendUser(
            @PathVariable("userId") Long userId,
            @RequestBody UnsuspendUserRequest request,
            @AuthenticationPrincipal UserDetails adminDetails
    ) throws UserNotFoundException, UnauthorizedAreaException {
        return adminUserService.unsuspendUser(adminDetails.getUsername(), userId, request);
    }

    /**
     * Cihaz engelleme
     */
    @PostMapping("/{userId}/device-ban")
    public ResponseMessage banUserDevice(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestBody Map<String, Object> request) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        String deviceId = (String) request.get("deviceId");
        String reason = (String) request.get("reason");

        return adminUserService.banUserDevice(userId, deviceId, reason, userDetails.getUsername());

    }

    // =============== 8. ŞÜPHELİ HAREKETLER VE GÜVENLİK ===============

    /**
     * Şüpheli giriş işlemlerini listeleme
     */
    @GetMapping("/suspicious-activities")
    public Page<Map<String, Object>> getSuspiciousActivities(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            @RequestParam(required = false) String activityType,
            Pageable pageable) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getSuspiciousActivities(
                startDate, endDate, activityType, pageable);

    }

    /**
     * Kullanıcı audit log'larını görüntüleme
     */
    @GetMapping("/{userId}/audit-logs")
    public Page<Map<String, Object>> getUserAuditLogs(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            @RequestParam(required = false) String action,
            Pageable pageable) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserAuditLogs(
                userId, startDate, endDate, action, pageable);
    }

    // =============== 9. ANALİTİK VE RAPORLAMA ===============

    /**
     * Kullanıcı istatistikleri
     */
    @GetMapping("/statistics")
    public Map<String, Object> getUserStatistics(
            @AuthenticationPrincipal UserDetails userDetails) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserStatistics();
    }

    /**
     * Kullanıcı giriş geçmişi raporlama
     */
    @GetMapping("/{userId}/login-history")
    public Page<LoginHistory> getUserLoginHistory(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            Pageable pageable) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserLoginHistory(userId, startDate, endDate, pageable);
    }

    /**
     * Kullanıcı arama geçmişi
     */
    @GetMapping("/{userId}/search-history")
    public Page<SearchHistoryDTO> getUserSearchHistory(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            Pageable pageable) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserSearchHistory(userId, startDate, endDate, pageable);
    }

    // =============== 10. BİLDİRİM VE İLETİŞİM ===============

    /**
     * Kullanıcıya bildirim gönderme
     */
    @PostMapping("/{userId}/send-notification")
    public ResponseMessage sendNotificationToUser(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestBody Map<String, Object> notificationData) throws UnauthorizedAccessException, UserNotFoundException {
        isAdminOrSuperAdmin(userDetails);

        String title = (String) notificationData.get("title");
        String message = (String) notificationData.get("message");
        String type = (String) notificationData.get("type");

        return adminUserService.sendNotificationToUser(userId, title, message, type, userDetails.getUsername());
    }

    /**
     * Toplu bildirim gönderme
     */
    @PostMapping("/bulk-notification")
    public ResponseMessage sendBulkNotification(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody Map<String, Object> notificationData) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        List<Long> userIds = (List<Long>) notificationData.get("userIds");
        String title = (String) notificationData.get("title");
        String message = (String) notificationData.get("message");
        String type = (String) notificationData.get("type");

        return adminUserService.sendBulkNotification(userIds, title, message, type, userDetails.getUsername());
    }

    // =============== 11. EKSTRA ÖZELLİKLER ===============

    /**
     * Kullanıcı bilgilerini PDF olarak e-posta ile gönderme
     */
    @GetMapping("/{userId}/export-pdf")
    public void exportUserPdf(@PathVariable("userId") Long userId, HttpServletResponse response) {
        try {
            byte[] pdfBytes = adminUserService.generateUserDataPdf(userId);

            response.setContentType("application/pdf");
            response.setHeader("Content-Disposition", "attachment; filename=user_" + userId + "_report.pdf");
            response.setContentLength(pdfBytes.length);

            ServletOutputStream os = response.getOutputStream();
            os.write(pdfBytes);
            os.flush();
        } catch (UserNotFoundException e) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    // Eğer mail ile PDF göndermek istersen ayrı endpoint
    @PostMapping("/{userId}/send-pdf-email")
    public ResponseMessage sendUserPdfByEmail(@PathVariable("userId") Long userId, @RequestParam String email) {
        try {
            adminUserService.sendUserDataPdfByEmail(userId, email);
            return new ResponseMessage("PDF mail olarak gönderildi.", true);
        } catch (UserNotFoundException e) {
            return new ResponseMessage("Kullanıcı bulunamadı.", false);
        } catch (Exception e) {
            return new ResponseMessage("PDF gönderilirken hata oluştu.", false);
        }
    }

    /**
     * Kullanıcı verilerini Excel olarak dışa aktarma
     */
    @GetMapping("/export-excel")
    public void exportUsersToExcel(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) List<Long> userIds,
            @RequestParam(required = false) UserStatus status,
            @RequestParam(required = false) Role role,
            HttpServletResponse response) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        adminUserService.exportUsersToExcel(userIds, status, role, response, userDetails.getUsername());
    }


    /**
     * Kullanıcı davranış analizi
     */
    @GetMapping("/{userId}/behavior-analysis")
    public Map<String, Object> getUserBehaviorAnalysis(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable("userId") Long userId,
            @RequestParam(required = false, defaultValue = "30") int days) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);

        return adminUserService.getUserBehaviorAnalysis(userId, days);
    }

    // =============== MEVCUT METOD (KORUNDU) ===============

    @PostMapping("/collective-sign-up")
    public List<ResponseMessage> collectiveSignUp(@AuthenticationPrincipal UserDetails userDetails,
                                                  @Valid @RequestBody CreateUserRequestList createUserRequestList,
                                                  HttpServletRequest httpServletRequest) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException, VerificationCodeStillValidException, UnauthorizedAccessException, AdminOrSuperAdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);
        return adminUserService.createAll(userDetails.getUsername(), createUserRequestList.getUsers(), httpServletRequest);
    }
}