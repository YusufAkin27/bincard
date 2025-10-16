package akin.city_card.user.service.concretes;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.geoIpService.GeoIpService;
import akin.city_card.geoIpService.GeoLocationData;
import akin.city_card.mail.EmailAttachment;
import akin.city_card.mail.EmailMessage;
import akin.city_card.mail.MailService;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.notification.model.NotificationPreferences;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.repository.NotificationRepository;
import akin.city_card.notification.service.FCMService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.exception.VerificationCodeStillValidException;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.security.repository.TokenRepository;
import akin.city_card.sms.SmsRequest;
import akin.city_card.sms.SmsService;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.request.PermanentDeleteRequest;
import akin.city_card.user.core.request.SuspendUserRequest;
import akin.city_card.user.core.request.UnsuspendUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import akin.city_card.user.model.*;
import akin.city_card.user.repository.LoginHistoryRepository;
import akin.city_card.user.repository.SearchHistoryRepository;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.abstracts.AdminUserService;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.wallet.exceptions.AdminOrSuperAdminNotFoundException;
import akin.city_card.wallet.repository.WalletRepository;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import jakarta.persistence.criteria.JoinType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminUserManager implements AdminUserService {
    private final UserRepository userRepository;
    private final UserConverter userConverter;
    private final GeoIpService geoIpService;
    private final SecurityUserRepository securityUserRepository;
    private final FCMService fcmService;
    private final TokenRepository tokenRepository;
    private final NotificationRepository notificationRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final AuditLogRepository auditLogRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final WalletRepository walletRepository;
    private final SearchHistoryRepository searchHistoryRepository;
    private final SmsService smsService;
    private final MailService mailService;

    @Override
    public PageDTO<CacheUserDTO> getAllUsers(Pageable pageable, String username, HttpServletRequest httpServletRequest) throws AdminNotFoundException {
        Page<User> userPage = userRepository.findAll(pageable);

        // Admin loglama
        SecurityUser currentAdmin = securityUserRepository.findByUserNumber(username).orElseThrow(AdminNotFoundException::new); // Mevcut admin bilgisi
        updateDeviceInfoAndCreateAuditLog(
                currentAdmin,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_LIST_USERS,
                "Tüm kullanıcıların listelenmesi",
                null,
                "Toplam kullanıcı sayısı: " + userPage.getTotalElements()
        );

        return new PageDTO<>(userPage.map(userConverter::toCacheUserDTO));
    }


    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp.trim();
        }

        return request.getRemoteAddr();
    }

    public DeviceInfo buildDeviceInfoFromRequest(HttpServletRequest httpRequest, GeoIpService geoIpService) {
        String ipAddress = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        String deviceType = "Unknown";
        if (userAgent != null) {
            String uaLower = userAgent.toLowerCase();
            if (uaLower.contains("mobile")) deviceType = "Mobile";
            else if (uaLower.contains("tablet")) deviceType = "Tablet";
            else deviceType = "Desktop";
        }

        GeoLocationData geoData = geoIpService.getGeoData(ipAddress);
        return DeviceInfo.builder()
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceType(deviceType)
                .city(Optional.ofNullable(geoData).map(GeoLocationData::getCity).orElse(null))
                .region(Optional.ofNullable(geoData).map(GeoLocationData::getRegion).orElse(null))
                .timezone(Optional.ofNullable(geoData).map(GeoLocationData::getTimezone).orElse(null))
                .org(Optional.ofNullable(geoData).map(GeoLocationData::getOrg).orElse(null))
                .build();
    }

    public void updateDeviceInfoAndCreateAuditLog(
            SecurityUser user,
            HttpServletRequest httpRequest,
            GeoIpService geoIpService,
            ActionType action,
            String description,
            Double amount,
            String metadata
    ) {
        DeviceInfo deviceInfo = buildDeviceInfoFromRequest(httpRequest, geoIpService);

        String referer = httpRequest.getHeader("Referer");
        String fullMetadata = (metadata == null ? "" : metadata + ", ") + (referer != null ? "Referer: " + referer : "");

        user.setCurrentDeviceInfo(deviceInfo);

        createAuditLog(
                user,
                action,
                description,
                deviceInfo,
                user.getId(),
                user.getRoles().toString(),
                amount,
                fullMetadata,
                referer

        );
    }

    public void createAuditLog(SecurityUser user,
                               ActionType action,
                               String description,
                               DeviceInfo deviceInfo,
                               Long targetEntityId,
                               String targetEntityType,
                               Double amount,
                               String metadata,
                               String referer) {

        AuditLog auditLog = new AuditLog();
        auditLog.setUser(user);
        auditLog.setAction(action);
        auditLog.setDescription(description);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setDeviceInfo(deviceInfo);
        auditLog.setTargetEntityId(targetEntityId);
        auditLog.setTargetEntityType(targetEntityType);
        auditLog.setAmount(amount);
        auditLog.setMetadata(metadata);
        auditLog.setReferer(referer);

        auditLogRepository.save(auditLog);
    }

    @Override
    public PageDTO<CacheUserDTO> searchUsers(String query, Pageable pageable, String username, HttpServletRequest httpServletRequest) throws AdminNotFoundException {
        Specification<User> spec = (root, cq, cb) -> cb.conjunction();

        if (query != null && !query.isBlank()) {
            String likeQuery = "%" + query.toLowerCase() + "%";

            spec = spec.and((root, cq, cb) -> {
                var rolesJoin = root.joinSet("roles", JoinType.LEFT);

                return cb.or(
                        cb.like(cb.lower(root.get("name")), likeQuery),
                        cb.like(cb.lower(root.get("surname")), likeQuery),
                        cb.like(cb.lower(root.get("email")), likeQuery),
                        cb.like(cb.lower(root.get("phone")), likeQuery),
                        cb.like(cb.lower(root.get("userNumber")), likeQuery),
                        cb.like(cb.lower(root.get("status").as(String.class)), likeQuery),
                        cb.like(cb.lower(rolesJoin.get("name").as(String.class)), likeQuery),
                        cb.like(cb.lower(root.get("emailVerified").as(String.class)), likeQuery),
                        cb.like(cb.lower(root.get("phoneVerified").as(String.class)), likeQuery)
                );
            });
        }

        Page<User> userPage = userRepository.findAll(spec, pageable);

        SecurityUser currentAdmin = securityUserRepository
                .findByUserNumber(username)
                .orElseThrow(AdminNotFoundException::new);

        String metadata = String.format(
                "Arama sorgusu: %s, Toplam sonuç: %d, Sayfa numarası: %d, Sayfa boyutu: %d",
                query != null ? query : "",
                userPage.getTotalElements(),
                pageable.getPageNumber(),
                pageable.getPageSize()
        );

        updateDeviceInfoAndCreateAuditLog(
                currentAdmin,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_SEARCH_USERS,
                "Kullanıcı arama işlemi",
                null,
                metadata
        );

        return new PageDTO<>(userPage.map(userConverter::toCacheUserDTO));
    }


    @Override
    @Transactional
    public ResponseMessage bulkUpdateUserStatus(List<Long> userIds, UserStatus newStatus, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException {
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username).orElseThrow(AdminOrSuperAdminNotFoundException::new);

        List<User> users = userRepository.findAllById(userIds);
        for (User user : users) {
            user.setStatus(newStatus);
        }
        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_BULK_UPDATE_USER_STATUS,
                "Toplu kullanıcı durumu güncelleme",
                null,
                "Yeni durum: " + newStatus + ", Etkilenen kullanıcı ID'leri: " + userIds
        );

        return new ResponseMessage("kullanıcıların durumları değiştirildi.", true);
    }

    @Override
    public ResponseMessage bulkDeleteUsers(List<Long> userIds, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException {
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username).orElseThrow(AdminOrSuperAdminNotFoundException::new);

        List<User> users = userRepository.findAllById(userIds);
        for (User user : users) {
            user.setStatus(UserStatus.DELETED);
        }
        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_BULK_DELETE_USERS,
                "Toplu kullanıcı silme işlemi",
                null,
                "Silinen kullanıcı ID'leri: " + userIds
        );

        return new ResponseMessage("Kullanıcılar silindi.", true);

    }

    @Override
    public CacheUserDTO getUserById(Long userId, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminOrSuperAdminNotFoundException {
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username).orElseThrow(AdminOrSuperAdminNotFoundException::new);

        User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_GET_USER_BY_ID,
                "Kullanıcı bilgisi görüntülendi",
                null,
                "Kullanıcı ID: " + userId
        );

        return userConverter.toCacheUserDTO(user);
    }

    @Override
    public Map<String, Object> getUserDeviceInfo(Long userId, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminNotFoundException {
        User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
        List<DeviceHistory> deviceHistories = user.getDeviceHistory();
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username).orElseThrow(AdminNotFoundException::new);
        Map<String, Object> result = new HashMap<>();

        // Aktif cihazlar
        List<Map<String, ? extends Comparable<? extends Comparable<?>>>> activeDevices = deviceHistories.stream()
                .filter(DeviceHistory::getIsActive)
                .filter(device -> !device.getIsDeleted())
                .map(device -> Map.of(
                        "deviceId", device.getDeviceId() != null ? device.getDeviceId() : "N/A",
                        "deviceName", device.getDeviceName() != null ? device.getDeviceName() : "Bilinmeyen Cihaz",
                        "deviceType", device.getDeviceType() != null ? device.getDeviceType() : "N/A",
                        "operatingSystem", device.getOperatingSystem() != null ? device.getOperatingSystem() : "N/A",
                        "ipAddress", device.getIpAddress() != null ? device.getIpAddress() : "N/A",
                        "city", device.getCity() != null ? device.getCity() : "Bilinmeyen",
                        "lastActiveAt", device.getLastActiveAt(),
                        "loginCount", device.getLoginCount(),
                        "isTrusted", device.getIsTrusted(),
                        "isBanned", device.getIsBanned()
                ))
                .collect(Collectors.toList());

        // Engelli cihazlar
        List<Map<String, ? extends Comparable<? extends Comparable<?>>>> bannedDevices = deviceHistories.stream()
                .filter(DeviceHistory::getIsBanned)
                .map(device -> Map.of(
                        "deviceId", device.getDeviceId() != null ? device.getDeviceId() : "N/A",
                        "deviceName", device.getDeviceName() != null ? device.getDeviceName() : "Bilinmeyen Cihaz",
                        "banReason", device.getBanReason() != null ? device.getBanReason() : "Sebep belirtilmemiş",
                        "bannedAt", device.getBannedAt(),
                        "bannedBy", device.getBannedBy() != null ? device.getBannedBy() : "Sistem"
                ))
                .collect(Collectors.toList());

        // Son 10 IP adresi
        List<String> recentIPs = deviceHistories.stream()
                .filter(device -> device.getIpAddress() != null)
                .sorted((d1, d2) -> d2.getLastSeenAt().compareTo(d1.getLastSeenAt()))
                .map(DeviceHistory::getIpAddress)
                .distinct()
                .limit(10)
                .collect(Collectors.toList());

        result.put("activeDevices", activeDevices);
        result.put("bannedDevices", bannedDevices);
        result.put("recentIpAddresses", recentIPs);
        result.put("totalDeviceCount", deviceHistories.size());
        result.put("activeDeviceCount", activeDevices.size());
        result.put("bannedDeviceCount", bannedDevices.size());

        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_GET_USER_DEVICE_INFO,
                "Kullanıcı cihaz bilgileri görüntülendi",
                null,
                "Kullanıcı ID: " + userId
        );

        return result;
    }

    @Override
    @Transactional
    public ResponseMessage assignRolesToUser(Long userId, Set<Role> roles, String username, HttpServletRequest httpServletRequest)
            throws AdminOrSuperAdminNotFoundException {

        User user = userRepository.findById(userId)
                .orElseThrow(AdminOrSuperAdminNotFoundException::new);
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminOrSuperAdminNotFoundException::new);
        user.setRoles(roles);

        userRepository.save(user);

        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_ASSIGN_ROLES,
                "Kullanıcıya roller atandı",
                null,
                "Kullanıcı ID: " + userId + ", Roller: " + roles
        );
        return new ResponseMessage("Rol güncellendi " + userId, true);
    }


    @Override
    @Transactional
    public ResponseMessage removeRolesFromUser(Long userId, Set<Role> roles, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        Set<Role> currentRoles = user.getRoles();
        boolean changed = false;

        for (Role role : roles) {
            if (currentRoles.contains(role)) {
                currentRoles.remove(role);
                changed = true;
            }
        }

        if (!changed) {
            return new ResponseMessage("Rol bulunamadı" + userId, false);
        }

        user.setRoles(currentRoles);
        userRepository.save(user);

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminOrSuperAdminNotFoundException::new);
        user.setRoles(roles);

        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_REMOVE_ROLES,
                "Kullanıcıdan roller kaldırıldı",
                null,
                "Kullanıcı ID: " + userId + ", Roller: " + roles
        );

        return new ResponseMessage("Removed roles successfully from user " + userId, true);
    }

    @Override
    @Transactional
    public ResponseMessage bulkAssignRoles(List<Long> userIds, Set<Role> roles, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminNotFoundException {
        List<Long> updatedUsers = new ArrayList<>();

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminNotFoundException::new);

        for (Long userId : userIds) {
            User user = userRepository.findById(userId)
                    .orElseThrow(UserNotFoundException::new);

            Set<Role> currentRoles = user.getRoles();
            boolean changed = false;

            for (Role role : roles) {
                if (!currentRoles.contains(role)) {
                    currentRoles.add(role);
                    changed = true;
                }
            }

            if (changed) {
                user.setRoles(currentRoles);
                userRepository.save(user);
                updatedUsers.add(userId);
            }
        }
        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_BULK_ASSIGN_ROLES,
                "Birden fazla kullanıcıya roller atandı",
                null,
                "Kullanıcı ID listesi: " + userIds + ", Roller: " + roles
        );

        return new ResponseMessage("Roles assigned to users: " + updatedUsers, true);
    }

    @Override
    @Transactional
    public ResponseMessage resetUserPassword(Long userId, String newPassword, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminNotFoundException {
        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);

        userRepository.save(user);

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminNotFoundException::new);


        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_RESET_PASSWORD,
                "Kullanıcı şifresi sıfırlandı",
                null,
                "Kullanıcı ID: " + userId
        );
        return new ResponseMessage("Password reset successfully for user " + userId, true);
    }


    @Override
    @Transactional
    public ResponseMessage updateEmailVerificationStatus(Long userId, boolean verified, String username, HttpServletRequest httpServletRequest)
            throws AdminOrSuperAdminNotFoundException, UserNotFoundException {

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminOrSuperAdminNotFoundException::new);

        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_UPDATE_EMAIL_VERIFICATION,
                "Kullanıcı email doğrulama durumu güncellendi",
                null,
                "Kullanıcı ID: " + userId + ", Yeni email doğrulama durumu: " + verified
        );

        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        user.setEmailVerified(verified);
        userRepository.save(user);

        return new ResponseMessage("Email doğrulama durumu güncellendi: " + verified, true);
    }

    @Override
    @Transactional
    public ResponseMessage updatePhoneVerificationStatus(Long userId, boolean verified, String username, HttpServletRequest httpServletRequest)
            throws AdminOrSuperAdminNotFoundException, UserNotFoundException {

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(AdminOrSuperAdminNotFoundException::new);

        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.ADMIN_UPDATE_PHONE_VERIFICATION,
                "Kullanıcı telefon doğrulama durumu güncellendi",
                null,
                "Kullanıcı ID: " + userId + ", Yeni telefon doğrulama durumu: " + verified
        );

        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        user.setPhoneVerified(verified);
        userRepository.save(user);

        return new ResponseMessage("Telefon doğrulama durumu güncellendi: " + verified, true);
    }


    @Override
    @Transactional
    public ResponseMessage banUserDevice(Long userId, String deviceId, String reason, String username) {
        try {
            User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
            SecurityUser admin = securityUserRepository.findByUserNumber(username)
                    .orElseThrow(AdminOrSuperAdminNotFoundException::new);

            DeviceHistory deviceToban = user.getDeviceHistory().stream()
                    .filter(device -> deviceId.equals(device.getDeviceId()))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("Cihaz bulunamadı"));

            deviceToban.setIsBanned(true);
            deviceToban.setBanReason(reason);
            deviceToban.setBannedAt(LocalDateTime.now());
            deviceToban.setBannedBy(username);
            deviceToban.setIsActive(false);

            userRepository.save(user);

            // Audit log oluştur
            createAuditLog(
                    admin,
                    ActionType.DEVICE_BANNED,
                    String.format("Cihaz engellendi - Kullanıcı: %s, Cihaz: %s, Sebep: %s",
                            user.getUserNumber(), deviceToban.getDeviceName(), reason),
                    null,
                    userId,
                    "User",
                    null,
                    "DeviceId: " + deviceId,
                    null
            );

            // Kullanıcıya bildirim gönder
            fcmService.sendNotificationToToken(
                    user,
                    "Cihaz Engellendi",
                    "Cihazınız güvenlik nedeniyle engellenmiştir. Detaylar için destek ekibiyle iletişime geçin.",
                    NotificationType.WARNING,
                    null
            );

            return new ResponseMessage("Cihaz başarıyla engellendi.", true);

        } catch (Exception e) {
            log.error("Cihaz engelleme hatası: {}", e.getMessage());
            return new ResponseMessage("Cihaz engellenirken hata oluştu: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage banIpAddress(String ipAddress, String reason, LocalDateTime expiresAt, String username) {
        try {
            SecurityUser admin = securityUserRepository.findByUserNumber(username)
                    .orElseThrow(AdminOrSuperAdminNotFoundException::new);

            // IP adresini kullanan tüm kullanıcıları bul
            List<User> affectedUsers = userRepository.findAll().stream()
                    .filter(user -> user.getDeviceHistory().stream()
                            .anyMatch(device -> ipAddress.equals(device.getIpAddress())))
                    .toList();

            // IP adresine ait tüm cihaz geçmişlerini güncelle
            for (User user : affectedUsers) {
                List<DeviceHistory> devicesWithIP = user.getDeviceHistory().stream()
                        .filter(device -> ipAddress.equals(device.getIpAddress()))
                        .toList();

                for (DeviceHistory device : devicesWithIP) {
                    device.setIsBanned(true);
                    device.setBanReason("IP Adresi Engellendi: " + reason);
                    device.setBannedAt(LocalDateTime.now());
                    device.setBannedBy(username);
                    device.setIsActive(false);
                }

                userRepository.save(user);

                // Etkilenen kullanıcılara bildirim gönder
                fcmService.sendNotificationToToken(
                        user,
                        "Güvenlik Uyarısı",
                        "IP adresiniz güvenlik nedeniyle engellenmiştir. Destek ekibiyle iletişime geçin.",
                        NotificationType.WARNING,
                        null
                );
            }

            // Audit log oluştur
            createAuditLog(
                    admin,
                    ActionType.IP_BANNED,
                    String.format("IP adresi engellendi - IP: %s, Sebep: %s, Etkilenen kullanıcı sayısı: %d",
                            ipAddress, reason, affectedUsers.size()),
                    null,
                    null,
                    "System",
                    null,
                    String.format("IP: %s, ExpiresAt: %s", ipAddress, expiresAt),
                    null
            );

            return new ResponseMessage(
                    String.format("IP adresi başarıyla engellendi. %d kullanıcı etkilendi.", affectedUsers.size()),
                    true
            );

        } catch (Exception e) {
            log.error("IP engelleme hatası: {}", e.getMessage());
            return new ResponseMessage("IP engellenirken hata oluştu: " + e.getMessage(), false);
        }
    }

    @Override
    public ResponseMessage suspendUser(String username, Long userId, SuspendUserRequest request) {
        return null;
    }

    @Override
    public ResponseMessage permanentlyDeleteUser(String username, Long userId, PermanentDeleteRequest request) {
        return null;
    }

    @Override
    public ResponseMessage unsuspendUser(String username, Long userId, UnsuspendUserRequest request) {
        return null;
    }

    @Override
    public List<Map<String, Object>> getUserActiveSessions(Long userId, HttpServletRequest httpServletRequest) {
        try {
            User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);

            // Aktif cihazları bul (son 30 dakika içinde aktif olan)
            LocalDateTime thirtyMinutesAgo = LocalDateTime.now().minusMinutes(30);

            return user.getDeviceHistory().stream()
                    .filter(DeviceHistory::getIsActive)
                    .filter(device -> !device.getIsBanned())
                    .filter(device -> !device.getIsDeleted())
                    .filter(device -> device.getLastActiveAt() != null &&
                            device.getLastActiveAt().isAfter(thirtyMinutesAgo))
                    .map(device -> {
                        Map<String, Object> session = new HashMap<>();
                        session.put("sessionId", device.getDeviceId());
                        session.put("deviceName", device.getDeviceName());
                        session.put("deviceType", device.getDeviceType());
                        session.put("operatingSystem", device.getOperatingSystem());
                        session.put("ipAddress", device.getIpAddress());
                        session.put("city", device.getCity());
                        session.put("lastActiveAt", device.getLastActiveAt());
                        session.put("loginCount", device.getLoginCount());
                        session.put("isTrusted", device.getIsTrusted());
                        session.put("browserName", device.getBrowserName());
                        session.put("appVersion", device.getAppVersion());
                        return session;
                    })
                    .sorted((s1, s2) -> {
                        LocalDateTime time1 = (LocalDateTime) s1.get("lastActiveAt");
                        LocalDateTime time2 = (LocalDateTime) s2.get("lastActiveAt");
                        return time2.compareTo(time1); // En son aktif olan üstte
                    })
                    .collect(Collectors.toList());

        } catch (Exception e) {
            log.error("Aktif oturum bilgileri alınırken hata: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    @Override
    @Transactional
    public ResponseMessage terminateUserSession(Long userId, String sessionId, String username, HttpServletRequest httpServletRequest) {
        try {
            User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
            SecurityUser admin = securityUserRepository.findByUserNumber(username)
                    .orElseThrow(AdminOrSuperAdminNotFoundException::new);

            DeviceHistory deviceToTerminate = user.getDeviceHistory().stream()
                    .filter(device -> sessionId.equals(device.getDeviceId()))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("Oturum bulunamadı"));

            // Oturumu sonlandır
            deviceToTerminate.setIsActive(false);
            deviceToTerminate.setLastActiveAt(LocalDateTime.now());
            deviceToTerminate.setFcmToken(null); // FCM token'ı temizle

            userRepository.save(user);

            // Token'ları temizle (eğer token repository'niz varsa)
            if (tokenRepository != null) {
                tokenRepository.deleteAllTokensByUser(user);
            }

            // Audit log oluştur
            createAuditLog(
                    admin,
                    ActionType.SESSION_TERMINATED,
                    String.format("Kullanıcı oturumu sonlandırıldı - Kullanıcı: %s, Cihaz: %s",
                            user.getUserNumber(), deviceToTerminate.getDeviceName()),
                    null,
                    userId,
                    "User",
                    null,
                    "SessionId: " + sessionId,
                    null
            );

            // Kullanıcıya bildirim gönder (diğer cihazlarına)
            fcmService.sendNotificationToToken(
                    user,
                    "Oturum Sonlandırıldı",
                    "Bir oturumunuz yönetici tarafından sonlandırıldı.",
                    NotificationType.INFO,
                    null
            );

            return new ResponseMessage("Oturum başarıyla sonlandırıldı.", true);

        } catch (Exception e) {
            log.error("Oturum sonlandırma hatası: {}", e.getMessage());
            return new ResponseMessage("Oturum sonlandırılırken hata oluştu: " + e.getMessage(), false);
        }
    }

    @Override
    public Page<LoginHistory> getUserLoginHistory(Long userId, String startDate, String endDate, Pageable pageable) {
        try {
            User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);

            LocalDateTime start = null;
            LocalDateTime end = null;

            if (startDate != null && !startDate.isBlank()) {
                start = LocalDateTime.parse(startDate + "T00:00:00");
            }
            if (endDate != null && !endDate.isBlank()) {
                end = LocalDateTime.parse(endDate + "T23:59:59");
            }

            // Repository'de bu metodu tanımlamanız gerekecek
            if (start != null && end != null) {
                return loginHistoryRepository.findByUserAndLoginAtBetweenOrderByLoginAtDesc(user, start, end, pageable);
            } else if (start != null) {
                return loginHistoryRepository.findByUserAndLoginAtAfterOrderByLoginAtDesc(user, start, pageable);
            } else if (end != null) {
                return loginHistoryRepository.findByUserAndLoginAtBeforeOrderByLoginAtDesc(user, end, pageable);
            } else {
                return loginHistoryRepository.findByUserOrderByLoginAtDesc(user, pageable);
            }

        } catch (Exception e) {
            log.error("Giriş geçmişi alınırken hata: {}", e.getMessage());
            return Page.empty(pageable);
        }
    }

    @Override
    public Page<Map<String, Object>> getUserAuditLogs(Long userId, String startDate, String endDate, String action, Pageable pageable) {
        try {
            User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);

            LocalDateTime start = null;
            LocalDateTime end = null;
            ActionType actionType = null;

            if (startDate != null && !startDate.isBlank()) {
                start = LocalDateTime.parse(startDate + "T00:00:00");
            }
            if (endDate != null && !endDate.isBlank()) {
                end = LocalDateTime.parse(endDate + "T23:59:59");
            }
            if (action != null && !action.isBlank()) {
                try {
                    actionType = ActionType.valueOf(action.toUpperCase());
                } catch (IllegalArgumentException e) {
                    log.warn("Geçersiz aksiyon türü: {}", action);
                }
            }

            Page<AuditLog> auditLogs = auditLogRepository.findAuditLogsByFilters(
                    user, start, end, actionType, pageable);

            return auditLogs.map(auditLog -> {
                Map<String, Object> logMap = new HashMap<>();
                logMap.put("id", auditLog.getId());
                logMap.put("action", auditLog.getAction().toString());
                logMap.put("description", auditLog.getDescription());
                logMap.put("timestamp", auditLog.getTimestamp());
                logMap.put("ipAddress", auditLog.getDeviceInfo() != null ? auditLog.getDeviceInfo().getIpAddress() : null);
                logMap.put("city", auditLog.getDeviceInfo() != null ? auditLog.getDeviceInfo().getCity() : null);
                logMap.put("deviceType", auditLog.getDeviceInfo() != null ? auditLog.getDeviceInfo().getDeviceType() : null);
                logMap.put("userAgent", auditLog.getDeviceInfo() != null ? auditLog.getDeviceInfo().getUserAgent() : null);
                logMap.put("metadata", auditLog.getMetadata());
                logMap.put("amount", auditLog.getAmount());
                return logMap;
            });

        } catch (Exception e) {
            log.error("Audit log'ları alınırken hata: {}", e.getMessage());
            return Page.empty(pageable);
        }
    }

    @Override
    public Map<String, Object> getUserStatistics() {
        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countByStatus(UserStatus.ACTIVE);
        long deletedUsers = userRepository.countByStatus(UserStatus.DELETED);
        long walletActivatedUsers = userRepository.countByWalletActivated(true);

        BigDecimal totalWalletBalance = walletRepository.getTotalBalance();

        Map<Role, Long> roleCounts = userRepository.findAll().stream()
                .flatMap(u -> u.getRoles().stream())
                .collect(Collectors.groupingBy(
                        role -> role,
                        Collectors.counting()
                ));

        return Map.of(
                "totalUsers", totalUsers,
                "activeUsers", activeUsers,
                "deletedUsers", deletedUsers,
                "walletActivatedUsers", walletActivatedUsers,
                "totalWalletBalance", totalWalletBalance,
                "roleCounts", roleCounts
        );
    }


    @Override
    @Transactional
    public List<ResponseMessage> createAll(String username, List<CreateUserRequest> createUserRequests, HttpServletRequest httpServletRequest) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException, VerificationCodeStillValidException, AdminOrSuperAdminNotFoundException {
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username).orElseThrow(AdminOrSuperAdminNotFoundException::new);

        List<ResponseMessage> responseMessages = new ArrayList<>();
        for (CreateUserRequest createUserRequest : createUserRequests) {
            responseMessages.add(userService.create(createUserRequest, httpServletRequest));
        }

        if (securityUser.getCurrentDeviceInfo() == null) {
            securityUser.setCurrentDeviceInfo(new DeviceInfo());
        }


        updateDeviceInfoAndCreateAuditLog(
                securityUser,
                httpServletRequest,
                geoIpService,
                ActionType.BULK_USER_CREATED,
                createUserRequests.size() + " adet kullanıcı topluca eklendi.",
                null,
                null
        );


        return responseMessages;
    }

    @Override
    public Page<Map<String, Object>> getSuspiciousActivities(String startDate, String endDate, String activityType, Pageable pageable) {
        try {
            LocalDateTime start = null;
            LocalDateTime end = null;

            if (startDate != null && !startDate.isBlank()) {
                start = LocalDateTime.parse(startDate + "T00:00:00");
            }
            if (endDate != null && !endDate.isBlank()) {
                end = LocalDateTime.parse(endDate + "T23:59:59");
            }

            // Şüpheli aktiviteler için özel kriterler
            List<ActionType> suspiciousActions = Arrays.asList(
                    ActionType.LOGIN_FAILED,
                    ActionType.MULTIPLE_LOGIN_ATTEMPTS,
                    ActionType.PASSWORD_RESET_SUSPICIOUS,
                    ActionType.DEVICE_BANNED,
                    ActionType.IP_BANNED,
                    ActionType.ACCOUNT_LOCKED
            );

            Page<AuditLog> suspiciousLogs = auditLogRepository.findSuspiciousActivities(
                    start, end, suspiciousActions, pageable);

            return suspiciousLogs.map(auditLog -> {
                Map<String, Object> activity = new HashMap<>();
                activity.put("id", auditLog.getId());
                activity.put("userId", auditLog.getUser().getId());
                activity.put("username", auditLog.getUser().getUserNumber());
                activity.put("action", auditLog.getAction().toString());
                activity.put("description", auditLog.getDescription());
                activity.put("timestamp", auditLog.getTimestamp());
                activity.put("ipAddress", auditLog.getDeviceInfo() != null ? auditLog.getDeviceInfo().getIpAddress() : null);
                activity.put("city", auditLog.getDeviceInfo() != null ? auditLog.getDeviceInfo().getCity() : null);
                activity.put("riskLevel", calculateRiskLevel(auditLog));
                activity.put("metadata", auditLog.getMetadata());
                return activity;
            });

        } catch (Exception e) {
            log.error("Şüpheli aktiviteler alınırken hata: {}", e.getMessage());
            return Page.empty(pageable);
        }
    }

    // Helper method for risk calculation
    private String calculateRiskLevel(AuditLog auditLog) {
        if (auditLog.getAction() == ActionType.LOGIN_FAILED ||
                auditLog.getAction() == ActionType.MULTIPLE_LOGIN_ATTEMPTS) {
            return "HIGH";
        }
        if (auditLog.getAction() == ActionType.DEVICE_BANNED ||
                auditLog.getAction() == ActionType.IP_BANNED) {
            return "CRITICAL";
        }
        return "MEDIUM";
    }


    @Override
    public Page<SearchHistoryDTO> getUserSearchHistory(Long userId, String startDate, String endDate, Pageable pageable) {
        LocalDateTime start = (startDate != null && !startDate.isBlank())
                ? LocalDateTime.parse(startDate) : null;
        LocalDateTime end = (endDate != null && !endDate.isBlank())
                ? LocalDateTime.parse(endDate) : null;

        Page<SearchHistory> page = searchHistoryRepository.findByUserIdAndDateRange(userId, start, end, pageable);

        return page.map(userConverter::toDto);
    }


    @Override
    public ResponseMessage sendNotificationToUser(Long userId, String title, String message, String type, String senderUsername) throws UserNotFoundException {
        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        NotificationPreferences prefs = user.getNotificationPreferences();
        if (prefs == null) {
            prefs = new NotificationPreferences(); // default
        }

        NotificationType notificationType = NotificationType.valueOf(type.toUpperCase());

        // Push Bildirim
        if (prefs.isPushEnabled() && prefs.isFcmActive()) {
            fcmService.sendNotificationToToken(user, title, message, notificationType, null);
        }

        if (prefs.isSmsEnabled()) {
            SmsRequest smsRequest = new SmsRequest();
            smsRequest.setTo(user.getUserNumber());
            smsRequest.setMessage(message);
            smsService.sendSms(smsRequest);
        }

        if (prefs.isEmailEnabled() && user.getProfileInfo().getEmail() != null) {
            String fullName = (user.getProfileInfo().getName() != null ? user.getProfileInfo().getName() : "") + " "
                    + (user.getProfileInfo().getSurname() != null ? user.getProfileInfo().getSurname() : "");

            String htmlContent = """
                    <html>
                      <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 30px;">
                        <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px;">
                          <h2 style="color: #333;">%s</h2>
                          <p>Merhaba <strong>%s</strong>,</p>
                          <p>%s</p>
                          <hr style="border: none; border-top: 1px solid #eee;">
                          <p style="font-size: 12px; color: #888;">Bu mesajı siz istemediyseniz lütfen dikkate almayın.</p>
                        </div>
                      </body>
                    </html>
                    """.formatted(title, fullName.trim(), message);

            EmailMessage emailMessage = new EmailMessage();
            emailMessage.setToEmail(user.getProfileInfo().getEmail());
            emailMessage.setSubject(title);
            emailMessage.setBody(htmlContent);
            emailMessage.setHtml(true);
            mailService.queueEmail(emailMessage);
        }

        fcmService.sendNotificationToToken(user, title, message, notificationType, null);
        return new ResponseMessage("Bildirim gönderildi.", true);
    }

    @Override
    public ResponseMessage sendBulkNotification(List<Long> userIds, String title, String message, String type, String username) {
        List<String> failedUsers = new ArrayList<>();

        userIds.parallelStream().forEach(userId -> {
            try {
                sendNotificationToUser(userId, title, message, type, username);
            } catch (Exception e) {
                failedUsers.add(userId.toString());
            }
        });

        if (failedUsers.isEmpty()) {
            return new ResponseMessage("Tüm kullanıcılara bildirim gönderildi.", true);
        } else {
            return new ResponseMessage("Bazı kullanıcılara bildirim gönderilemedi: " + String.join(", ", failedUsers), false);
        }
    }


    @Override
    public void exportUsersToExcel(List<Long> userIds, UserStatus status, Role role, HttpServletResponse response, String username) {
        try {
            List<User> users = userRepository.findUsersByFilters(userIds, status, role);

            Workbook workbook = new XSSFWorkbook();
            Sheet sheet = workbook.createSheet("Users");

            Row headerRow = sheet.createRow(0);
            String[] columns = {"ID", "Username", "Email", "Status", "Role", "Created At"};
            for (int i = 0; i < columns.length; i++) {
                Cell cell = headerRow.createCell(i);
                cell.setCellValue(columns[i]);
            }

            int rowIdx = 1;
            for (User user : users) {
                Row row = sheet.createRow(rowIdx++);

                row.createCell(0).setCellValue(user.getId());
                row.createCell(1).setCellValue(user.getUsername());
                row.createCell(2).setCellValue(user.getProfileInfo().getEmail());
                row.createCell(3).setCellValue(user.getStatus().name());
                row.createCell(4).setCellValue(user.getRoles().stream()
                        .map(Role::getAuthority)
                        .anyMatch(r -> r.equalsIgnoreCase(role.name())));
                row.createCell(5).setCellValue(user.getCreatedAt().toString());
            }

            response.setContentType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            String fileName = "users_export_" + System.currentTimeMillis() + ".xlsx";
            response.setHeader("Content-Disposition", "attachment; filename=" + fileName);

            workbook.write(response.getOutputStream());
            workbook.close();
            response.getOutputStream().flush();

        } catch (Exception e) {
            throw new RuntimeException("Excel export hatası: " + e.getMessage(), e);
        }
    }


    @Override
    public Map<String, Object> getUserBehaviorAnalysis(Long userId, int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);

        int loginCount = auditLogRepository.countLogins(userId, since);
        int logoutCount = auditLogRepository.countActions(userId, List.of(ActionType.LOGOUT), since);

        int passwordChanges = auditLogRepository.countActions(userId, List.of(ActionType.CHANGE_PASSWORD, ActionType.RESET_PASSWORD), since);

        int profileUpdates = auditLogRepository.countActions(userId, List.of(ActionType.UPDATE_PROFILE, ActionType.USER_PROFILE_UPDATED), since);

        List<ActionType> cardActions = List.of(
                ActionType.ADD_BUS_CARD,
                ActionType.DELETE_BUS_CARD,
                ActionType.BUS_CARD_TOP_UP,
                ActionType.BUS_CARD_TRANSFER,
                ActionType.UPDATE_BUS_CARD_ALIAS
        );
        int cardActivityCount = auditLogRepository.countActions(userId, cardActions, since);

        List<ActionType> notificationActions = List.of(ActionType.NOTIFICATION_RECEIVED, ActionType.NOTIFICATION_READ);
        int notificationsReceived = auditLogRepository.countActions(userId, notificationActions, since);

        int terminatedSessions = auditLogRepository.countActions(userId, List.of(ActionType.TERMINATE_SESSION, ActionType.TERMINATE_ALL_SESSIONS), since);

        List<AuditLog> recentActivities = auditLogRepository.findByUserSince(userId, since);

        Map<LocalDateTime, Long> activitiesPerDay = recentActivities.stream()
                .collect(Collectors.groupingBy(a -> a.getTimestamp().toLocalDate().atStartOfDay(), Collectors.counting()));

        LocalDateTime mostActiveDay = activitiesPerDay.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);
        Long mostActiveDayCount = activitiesPerDay.getOrDefault(mostActiveDay, 0L);

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("loginCount", loginCount);
        analysis.put("logoutCount", logoutCount);
        analysis.put("passwordChanges", passwordChanges);
        analysis.put("profileUpdates", profileUpdates);
        analysis.put("cardActivityCount", cardActivityCount);
        analysis.put("notificationsReceived", notificationsReceived);
        analysis.put("terminatedSessions", terminatedSessions);
        analysis.put("mostActiveDay", mostActiveDay);
        analysis.put("mostActiveDayActivityCount", mostActiveDayCount);
        analysis.put("days", days);

        return analysis;
    }


    public byte[] generateUserDataPdf(Long userId) throws UserNotFoundException {
        User user = userRepository.findById(userId)
                .orElseThrow(UserNotFoundException::new);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Document document = new Document(PageSize.A4, 36, 36, 54, 36);
            PdfWriter.getInstance(document, baos);
            document.open();

            // Font ayarları
            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, BaseColor.BLUE);
            Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, BaseColor.WHITE);
            Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 12, BaseColor.BLACK);

            // Başlık
            Paragraph title = new Paragraph("Kullanıcı Bilgileri Raporu", titleFont);
            title.setAlignment(Element.ALIGN_CENTER);
            title.setSpacingAfter(20);
            document.add(title);

            // Kullanıcı bilgileri tablosu
            PdfPTable table = new PdfPTable(2); // 2 sütunlu
            table.setWidthPercentage(80);
            table.setSpacingBefore(10f);
            table.setSpacingAfter(10f);
            table.setWidths(new float[]{2f, 4f});

            // Header hücreleri
            PdfPCell cell;

            cell = new PdfPCell(new Phrase("Alan", headerFont));
            cell.setBackgroundColor(BaseColor.GRAY);
            cell.setHorizontalAlignment(Element.ALIGN_CENTER);
            cell.setPadding(8);
            table.addCell(cell);

            cell = new PdfPCell(new Phrase("Değer", headerFont));
            cell.setBackgroundColor(BaseColor.GRAY);
            cell.setHorizontalAlignment(Element.ALIGN_CENTER);
            cell.setPadding(8);
            table.addCell(cell);

            // Satırlar
            addTableRow(table, "ID", String.valueOf(user.getId()), normalFont);
            addTableRow(table, "Ad", user.getProfileInfo().getName(), normalFont);
            addTableRow(table, "Soyad", user.getProfileInfo().getSurname(), normalFont);
            addTableRow(table, "Email", user.getProfileInfo().getEmail(), normalFont);
            addTableRow(table, "Telefon", user.getUserNumber(), normalFont);
            // İstersen daha fazla alan ekle

            document.add(table);

            // Tarih ve footer
            Paragraph footer = new Paragraph("Rapor oluşturulma tarihi: " + java.time.LocalDate.now().toString(), FontFactory.getFont(FontFactory.HELVETICA_OBLIQUE, 10, BaseColor.DARK_GRAY));
            footer.setAlignment(Element.ALIGN_RIGHT);
            document.add(footer);

            document.close();

            return baos.toByteArray();

        } catch (Exception e) {
            throw new RuntimeException("PDF oluşturulurken hata oluştu", e);
        }
    }

    @Override
    public void sendUserDataPdfByEmail(Long userId, String email) throws UserNotFoundException {
        // PDF byte dizisini oluştur
        byte[] pdfBytes = generateUserDataPdf(userId);

        // Email mesajını oluştur
        EmailMessage emailMessage = new EmailMessage();
        emailMessage.setToEmail(email);
        emailMessage.setSubject("Kullanıcı Bilgileri PDF Raporu");
        emailMessage.setBody("Sayın Admin,\n\nİstediğiniz kullanıcı bilgileri ekte PDF olarak gönderilmiştir.\n\nİyi çalışmalar.");
        emailMessage.setHtml(false);

        // PDF dosya eki oluştur
        EmailAttachment attachment = new EmailAttachment();
        attachment.setName("user_" + userId + "_report.pdf");
        attachment.setContent(pdfBytes);
        attachment.setContentType("application/pdf");
        attachment.setDisposition(EmailAttachment.ATTACHMENT);

        emailMessage.setAttachments(List.of(attachment));

        // Mail servisine gönderim kuyruğuna ekle
        mailService.queueEmail(emailMessage);
    }


    private void addTableRow(PdfPTable table, String key, String value, Font font) {
        PdfPCell cellKey = new PdfPCell(new Phrase(key, font));
        cellKey.setPadding(6);
        table.addCell(cellKey);

        PdfPCell cellValue = new PdfPCell(new Phrase(value != null ? value : "-", font));
        cellValue.setPadding(6);
        table.addCell(cellValue);
    }

}
