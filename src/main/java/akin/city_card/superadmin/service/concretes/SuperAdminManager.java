package akin.city_card.superadmin.service.concretes;

import akin.city_card.admin.core.converter.AuditLogConverter;
import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.*;
import akin.city_card.admin.repository.AdminApprovalRequestRepository;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.bus.model.BusRide;
import akin.city_card.bus.model.RideStatus;
import akin.city_card.bus.repository.BusRideRepository;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.security.exception.SuperAdminNotFoundException;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.superadmin.core.request.AddRoleAdminRequest;
import akin.city_card.superadmin.core.request.UpdateAdminRequest;
import akin.city_card.superadmin.core.response.AdminDetailsResponse;
import akin.city_card.superadmin.exceptions.AdminApprovalRequestNotFoundException;
import akin.city_card.superadmin.exceptions.AdminNotActiveException;
import akin.city_card.superadmin.exceptions.RequestAlreadyProcessedException;
import akin.city_card.superadmin.exceptions.ThisTelephoneAlreadyUsedException;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.superadmin.service.abstracts.SuperAdminService;
import akin.city_card.user.exceptions.EmailAlreadyExistsException;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.UserStatus;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class SuperAdminManager implements SuperAdminService {
    private final SuperAdminRepository superAdminRepository;
    private final AdminApprovalRequestRepository adminApprovalRequestRepository;
    private final AdminRepository adminRepository;
    private final BusRideRepository busRideRepository;
    private final AuditLogRepository auditLogRepository;
    private final AuditLogConverter auditLogConverter;
    private final UserRepository userRepository;
    private final SecurityUserRepository securityUserRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    @Transactional
    public ResponseMessage approveAdminRequest(String username, Long adminId) throws AdminNotFoundException, AdminApprovalRequestNotFoundException, RequestAlreadyProcessedException {
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (superAdmin == null) {
            throw new AdminNotFoundException();
        }
        List<AdminApprovalRequest> adminApprovalRequests = adminApprovalRequestRepository.findAll();
        AdminApprovalRequest request = adminApprovalRequests.stream().filter(adminApprovalRequest -> adminApprovalRequest.getAdmin().getId().equals(adminId)).findFirst().orElseThrow(AdminApprovalRequestNotFoundException::new);

        if (request.getStatus() != ApprovalStatus.PENDING) {
            throw new RequestAlreadyProcessedException();
        }

        request.setStatus(ApprovalStatus.APPROVED);
        request.setUpdateAt(LocalDateTime.now());
        request.setApprovedBy(superAdmin); // varsa
        adminApprovalRequestRepository.save(request);

        Admin admin = request.getAdmin();
        admin.setStatus(UserStatus.ACTIVE);
        admin.setSuperAdminApproved(true);
        admin.setApprovedAt(LocalDateTime.now());
        adminRepository.save(admin);

        return new ResponseMessage("Admin request approved successfully", true);
    }


    @Override
    @Transactional
    public ResponseMessage rejectAdminRequest(String username, Long adminId) throws AdminNotFoundException, RequestAlreadyProcessedException, AdminApprovalRequestNotFoundException {
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (superAdmin == null) {
            throw new AdminNotFoundException();
        }
        List<AdminApprovalRequest> adminApprovalRequests = adminApprovalRequestRepository.findAll();
        /*Admin Bulunamadığı için İsteği reddedilmiyor*/
        AdminApprovalRequest request = adminApprovalRequests.stream().filter(adminApprovalRequest -> adminApprovalRequest.getAdmin().getId().equals(adminId)).findFirst().orElseThrow(AdminApprovalRequestNotFoundException::new);

        if (request.getStatus() != ApprovalStatus.PENDING) {
            throw new RequestAlreadyProcessedException();
        }

        request.setStatus(ApprovalStatus.REJECTED);
        request.setUpdateAt(LocalDateTime.now());
        request.setApprovedBy(superAdmin); // varsa
        adminApprovalRequestRepository.save(request);

        Admin admin = request.getAdmin();
        admin.setStatus(UserStatus.INACTIVE);
        admin.setSuperAdminApproved(false);
        adminRepository.save(admin);
        return new ResponseMessage("Admin request rejected successfully", true);
    }

    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getDailyBusIncome(String username, LocalDate date) {
        LocalDateTime start = date.atStartOfDay();
        LocalDateTime end = date.atTime(23, 59, 59);

        List<BusRide> rides = busRideRepository.findByBoardingTimeBetweenAndBusDriverUserNumber(start, end, username);

        Map<String, BigDecimal> incomePerBus = new HashMap<>();

        for (BusRide ride : rides) {
            String plate = ride.getBus().getNumberPlate();
        }

        return new DataResponseMessage<>("başarılı", true, incomePerBus);
    }


    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getWeeklyBusIncome(String username, LocalDate startDate, LocalDate endDate) {
        LocalDateTime start = startDate.atStartOfDay();
        LocalDateTime end = endDate.atTime(23, 59, 59);

        List<BusRide> rides = busRideRepository.findByBoardingTimeBetweenAndBusDriverUserNumberAndStatus(
                start, end, username, RideStatus.SUCCESS);

        Map<String, BigDecimal> incomePerBus = new HashMap<>();

        for (BusRide ride : rides) {
            String plate = ride.getBus().getNumberPlate();
            incomePerBus.merge(plate, ride.getFareCharged(), BigDecimal::add);
        }

        return new DataResponseMessage<>("başarılı", true, incomePerBus);
    }


    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getMonthlyBusIncome(String username, int year, int month) {
        LocalDate startDate = LocalDate.of(year, month, 1);
        LocalDate endDate = startDate.withDayOfMonth(startDate.lengthOfMonth());

        return getWeeklyBusIncome(username, startDate, endDate);
    }


    @Override
    public DataResponseMessage<Map<String, BigDecimal>> getIncomeSummary(String username) {
        List<BusRide> rides = busRideRepository.findByBusDriverUserNumberAndStatus(username, RideStatus.SUCCESS);

        Map<String, BigDecimal> incomePerBus = new HashMap<>();

        for (BusRide ride : rides) {
            String plate = ride.getBus().getNumberPlate();
            incomePerBus.merge(plate, ride.getFareCharged(), BigDecimal::add);
        }

        return new DataResponseMessage<>("başarılı", true, incomePerBus);
    }


    @Override
    public DataResponseMessage<List<AdminApprovalRequest>> getPendingAdminRequest(String username, Pageable pageable) throws SuperAdminNotFoundException {
        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(username);
        if (superAdmin == null) {
            throw new SuperAdminNotFoundException();
        }

        Page<AdminApprovalRequest> pendingRequests = adminApprovalRequestRepository
                .findByStatus(ApprovalStatus.PENDING, pageable);

        return new DataResponseMessage<>("başarılı", true, pendingRequests.getContent());
    }

    @Override
    public DataResponseMessage<List<AuditLogDTO>> getAuditLogs(String fromDate, String toDate, String action, String username) {
        LocalDateTime from = (fromDate != null && !fromDate.isBlank()) ?
                LocalDate.parse(fromDate).atStartOfDay() :
                LocalDateTime.of(2000, 1, 1, 0, 0); // Güvenli başlangıç

        LocalDateTime to = (toDate != null && !toDate.isBlank()) ?
                LocalDate.parse(toDate).atTime(LocalTime.MAX) :
                LocalDateTime.now();

        // Action tipi çözümle
        ActionType actionType = null;
        if (action != null && !action.isBlank()) {
            try {
                actionType = ActionType.valueOf(action.toUpperCase());
            } catch (IllegalArgumentException e) {
                return new DataResponseMessage<>("başarılı", true, List.of()); // Geçersiz action -> boş dön
            }
        }

        // Kullanıcının SuperAdmin olup olmadığını kontrol et
        boolean isSuperAdmin = superAdminRepository.existsByUserNumber(username); // performanslı yöntem

        List<AuditLog> logs;

        if (isSuperAdmin) {
            // SuperAdmin ise tüm logları getir
            logs = (actionType != null)
                    ? auditLogRepository.findByActionAndTimestampBetween(actionType, from, to)
                    : auditLogRepository.findByTimestampBetween(from, to);
        } else {
            // Normal kullanıcı ise sadece kendi loglarını getir
            logs = (actionType != null)
                    ? auditLogRepository.findByUser_UserNumberAndActionAndTimestampBetween(username, actionType, from, to)
                    : auditLogRepository.findByUser_UserNumberAndTimestampBetween(username, from, to);
        }

        List<AuditLogDTO> dtoList = logs.stream().map(auditLogConverter::mapToDto).toList();
        return new DataResponseMessage<>("başarılı", true, dtoList);
    }

    @Override
    @Transactional
    public ResponseMessage addRole(String username, AddRoleAdminRequest addRoleAdminRequest)
            throws AdminNotFoundException, AdminNotActiveException {

        Admin admin = adminRepository.findById(addRoleAdminRequest.getAdminId())
                .orElseThrow(AdminNotFoundException::new);

        if (!admin.isEnabled()) {
            throw new AdminNotActiveException();
        }

        List<Role> requestedRoles = addRoleAdminRequest.getRoles();
        if (requestedRoles == null || requestedRoles.isEmpty()) {
            return new ResponseMessage("Rol verisi göndermelisin", false);
        }

        Set<Role> adminRoles = admin.getRoles();
        List<Role> addedRoles = new ArrayList<>();
        List<Role> alreadyHasRoles = new ArrayList<>();

        for (Role role : requestedRoles) {
            if (role == null) {
                continue;
            }

            if (!adminRoles.contains(role)) {
                adminRoles.add(role);
                addedRoles.add(role);
            } else {
                alreadyHasRoles.add(role);
            }
        }

        admin.setRoles(adminRoles);
        adminRepository.save(admin);

        StringBuilder message = new StringBuilder();
        if (!addedRoles.isEmpty()) {
            message.append("Added roles: ")
                    .append(addedRoles.stream().map(Role::name).toList())
                    .append(". ");
        }

        if (!alreadyHasRoles.isEmpty()) {
            message.append("Already had roles: ")
                    .append(alreadyHasRoles.stream().map(Role::name).toList())
                    .append(".");
        }

        return new ResponseMessage(message.toString().trim(), true);
    }

    @Override
    @Transactional
    public ResponseMessage removeRole(String username, AddRoleAdminRequest addRoleAdminRequest) throws AdminNotFoundException, AdminNotActiveException {

        Admin admin = adminRepository.findById(addRoleAdminRequest.getAdminId())
                .orElseThrow(AdminNotFoundException::new);

        if (!admin.isEnabled()) {
            throw new AdminNotActiveException();
        }

        List<Role> rolesToRemove = addRoleAdminRequest.getRoles();
        if (rolesToRemove == null || rolesToRemove.isEmpty()) {
            return new ResponseMessage("Silinicek Rol verisi yok", false);
        }

        Set<Role> currentRoles = admin.getRoles();
        List<Role> removedRoles = new ArrayList<>();
        List<Role> notFoundRoles = new ArrayList<>();

        for (Role role : rolesToRemove) {
            if (role == null) continue;

            if (currentRoles.contains(role)) {
                currentRoles.remove(role);
                removedRoles.add(role);
            } else {
                notFoundRoles.add(role);
            }
        }

        admin.setRoles(currentRoles);
        adminRepository.save(admin);

        // Bilgilendirme mesajı
        StringBuilder message = new StringBuilder();
        if (!removedRoles.isEmpty()) {
            message.append("Removed roles: ")
                    .append(removedRoles.stream().map(Role::name).toList())
                    .append(". ");
        }

        if (!notFoundRoles.isEmpty()) {
            message.append("Roles not assigned to admin: ")
                    .append(notFoundRoles.stream().map(Role::name).toList())
                    .append(".");
        }

        return new ResponseMessage(message.toString().trim(), true);
    }

    @Override
    public DataResponseMessage<List<String>> getAdminRoles(UserDetails userDetails, Long adminId) throws AdminNotActiveException, AdminNotFoundException {
        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        if (!admin.isEnabled()) {
            throw new AdminNotActiveException();
        }

        List<String> roleNames = admin.getRoles()
                .stream()
                .map(Role::name)
                .sorted() // isteğe bağlı: alfabetik sıralama
                .toList();

        return new DataResponseMessage<>("Admin roles retrieved successfully.", true, roleNames);
    }

    @Override
    @Transactional
    public ResponseMessage createAdmin(String username, CreateAdminRequest request)
            throws ThisTelephoneAlreadyUsedException, EmailAlreadyExistsException {

        // 1. Telefon numarası kontrolü
        if (securityUserRepository.existsByUserNumber(request.getTelephone())) {
            throw new ThisTelephoneAlreadyUsedException();
        }

        // 2. E-posta kontrolü
        if (securityUserRepository.existsByProfileInfoEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        // 3. Admin oluşturuluyor
        Admin admin = new Admin();
        admin.setUserNumber(request.getTelephone());
        admin.setPassword(passwordEncoder.encode(request.getPassword())); // Güvenlik için hashle
        admin.setStatus(UserStatus.ACTIVE);
        admin.setSuperAdminApproved(true);
        admin.setApprovedAt(LocalDateTime.now());
        admin.setRegisteredAt(LocalDateTime.now());
        admin.setCreatedAt(LocalDateTime.now());
        admin.setDeleted(false);
        admin.setEmailVerified(false);

        // 4. Profil bilgileri
        ProfileInfo profileInfo = new ProfileInfo();
        profileInfo.setName(request.getName());
        profileInfo.setSurname(request.getSurname());
        profileInfo.setEmail(request.getEmail());
        admin.setProfileInfo(profileInfo);

        // 5. Roller
        List<Role> roles = request.getRoles();
        if (roles == null || roles.isEmpty()) {
            admin.setRoles(Set.of(Role.ADMIN_ALL)); // Varsayılan olarak sadece ADMIN verilebilir
        } else {
            admin.setRoles(Set.copyOf(roles));
        }

        // 6. Audit Log
        AuditLog auditLog = new AuditLog();
        auditLog.setAction(ActionType.CREATE_ADMIN);
        auditLog.setDescription("Admin created: " + request.getTelephone());
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setTargetEntityId(null); // yeni admin ID henüz yok
        auditLog.setTargetEntityType("Admin");
        auditLog.setUser(admin); // işlemi yapan kullanıcıyı bağla
        auditLog.setDeviceInfo(admin.getCurrentDeviceInfo()); // helper metot ile alınabilir

        admin.setAuditLogs(List.of(auditLog));

        // 7. Kaydet
        adminRepository.save(admin);

        return new ResponseMessage("Admin created successfully", true);
    }

    @Override
    @Transactional
    public ResponseMessage updateAdmin(String username, Long adminId, UpdateAdminRequest request) throws AdminNotFoundException, AdminNotActiveException, EmailAlreadyExistsException {
        // 1. Admin kontrolü
        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        if (!admin.isEnabled()) {
            throw new AdminNotActiveException();
        }


        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            admin.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        if (admin.getProfileInfo() == null) {
            admin.setProfileInfo(new ProfileInfo());
        }

        ProfileInfo profileInfo = admin.getProfileInfo();

        if (request.getName() != null) {
            profileInfo.setName(request.getName());
        }

        if (request.getSurname() != null) {
            profileInfo.setSurname(request.getSurname());
        }

        if (request.getEmail() != null && !request.getEmail().equals(profileInfo.getEmail())) {
            if (securityUserRepository.existsByProfileInfoEmail(request.getEmail())) {
                throw new EmailAlreadyExistsException();
            }
            profileInfo.setEmail(request.getEmail());
        }

        admin.setProfileInfo(profileInfo);

        // 5. Roller güncellemesi
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            admin.setRoles(Set.copyOf(request.getRoles()));
        }

        admin.setUpdatedAt(LocalDateTime.now());

        // 6. Audit log
        AuditLog auditLog = new AuditLog();
        auditLog.setAction(ActionType.UPDATE_ADMIN);
        auditLog.setDescription("Admin güncellendi Superadmin tarafından " + adminId);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setTargetEntityId(adminId);
        auditLog.setTargetEntityType("Admin");
        auditLog.setUser(admin);
        auditLog.setDeviceInfo(admin.getCurrentDeviceInfo());

        admin.getAuditLogs().add(auditLog);

        // 7. Kaydet
        adminRepository.save(admin);

        return new ResponseMessage("Admin updated successfully.", true);
    }

    @Override
    @Transactional
    public ResponseMessage deleteAdmin(String username, Long adminId) throws AdminNotFoundException {
        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        if (admin.isDeleted()) {
            return new ResponseMessage("Admin is already deleted.", false);
        }

        admin.setStatus(UserStatus.INACTIVE);
        admin.setDeleted(true);
        admin.setUpdatedAt(LocalDateTime.now());

        AuditLog auditLog = new AuditLog();
        auditLog.setAction(ActionType.DELETE_ADMIN);
        auditLog.setDescription("Admin soft-deleted: " + adminId);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setTargetEntityId(adminId);
        auditLog.setTargetEntityType("Admin");
        auditLog.setUser(admin);
        auditLog.setDeviceInfo(admin.getCurrentDeviceInfo());

        admin.getAuditLogs().add(auditLog);

        adminRepository.save(admin);

        return new ResponseMessage("Admin silindi.", true);
    }

    @Override
    @Transactional
    public ResponseMessage toggleAdminStatus(String username, Long adminId) throws AdminNotFoundException {
        // 1. Admin kontrolü
        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        if (admin.isDeleted()) {
            return new ResponseMessage("Admin silinmiş", false);
        }

        // 2. Durum ters çevrilir
        UserStatus currentStatus = admin.getStatus();
        UserStatus newStatus = currentStatus == UserStatus.ACTIVE ? UserStatus.INACTIVE : UserStatus.ACTIVE;
        admin.setStatus(newStatus);
        admin.setUpdatedAt(LocalDateTime.now());

        // 3. Audit log
        AuditLog auditLog = new AuditLog();
        auditLog.setAction(ActionType.UPDATE_ADMIN_STATUS);
        auditLog.setDescription("Admin status toggled: " + adminId + " → " + newStatus);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setTargetEntityId(adminId);
        auditLog.setTargetEntityType("Admin");
        auditLog.setUser(admin);
        auditLog.setDeviceInfo(admin.getCurrentDeviceInfo());

        admin.getAuditLogs().add(auditLog);

        // 4. Kaydet
        adminRepository.save(admin);

        return new ResponseMessage("Admin status changed to " + newStatus.name(), true);
    }

    @Override
    public DataResponseMessage<AdminDetailsResponse> getAdminDetails(String username, Long adminId) throws AdminNotFoundException {

        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        AdminDetailsResponse response = new AdminDetailsResponse();
        response.setId(admin.getId());
        response.setName(admin.getProfileInfo().getName());
        response.setEmail(admin.getProfileInfo().getEmail());
        response.setTelephone(admin.getUsername());
        response.setStatus(admin.getStatus().name());
        response.setRole(admin.getRoles().stream().map(Role::name).toList());
        response.setSuperAdminApproved(admin.isSuperAdminApproved());
        response.setApprovedAt(admin.getApprovedAt());
        response.setRegisteredAt(admin.getRegisteredAt());

        List<LoginHistory> history = admin.getLoginHistory();
        if (history != null && !history.isEmpty()) {
            LoginHistory lastLogin = history.stream()
                    .max(Comparator.comparing(LoginHistory::getLoginAt))
                    .orElse(null);

            if (lastLogin != null) {
                response.setLastLoginIp(lastLogin.getIpAddress());
                response.setLastLoginAt(lastLogin.getLoginAt());
            }

            response.setTotalLogins(history.size());
        } else {
            response.setLastLoginIp(null);
            response.setLastLoginAt(null);
            response.setTotalLogins(0);
        }


        response.setUpdatedAt(admin.getUpdatedAt());

        response.setEmailVerified(admin.isEmailVerified());
        response.setPhoneVerified(admin.isPhoneVerified());


        return new DataResponseMessage<>("Admin detayları başarıyla getirildi.", true,response);
    }

    @Override
    public DataResponseMessage<List<AdminDetailsResponse>> getAllAdmins(String username, String status, String role, String searchTerm, Pageable pageable) {

        Page<Admin> adminsPage;

        // Filtreleri uygula (status, role, searchTerm)
        if (searchTerm != null && !searchTerm.isEmpty()) {
            adminsPage = adminRepository.findByProfileInfo_NameContainingIgnoreCaseOrProfileInfo_EmailContainingIgnoreCaseOrUserNumberContainingIgnoreCase(
                    searchTerm, searchTerm, searchTerm, pageable);
        } else if (status != null && role != null) {
            adminsPage = adminRepository.findByStatusAndRole(status, role, pageable);
        } else if (status != null) {
            adminsPage = adminRepository.findByStatus(status, pageable);
        } else if (role != null) {
            adminsPage = adminRepository.findByRole(role, pageable);
        } else {
            adminsPage = adminRepository.findAll(pageable);
        }

        // Dönüştürme işlemi (Entity -> DTO)
        List<AdminDetailsResponse> responses = adminsPage.getContent().stream()
                .map(admin -> {
                    AdminDetailsResponse dto = new AdminDetailsResponse();
                    dto.setId(admin.getId());
                    dto.setName(admin.getProfileInfo().getName());
                    dto.setEmail(admin.getProfileInfo().getEmail());
                    dto.setTelephone(admin.getUserNumber());
                    dto.setStatus(admin.getStatus().name());
                    dto.setRole(admin.getRoles().stream().map(Role::name).toList());
                    dto.setSuperAdminApproved(admin.isSuperAdminApproved());
                    dto.setApprovedAt(admin.getApprovedAt());
                    dto.setRegisteredAt(admin.getRegisteredAt());

                    // Son giriş bilgileri
                    List<LoginHistory> history = admin.getLoginHistory();
                    if (history != null && !history.isEmpty()) {
                        LoginHistory lastLogin = history.stream()
                                .max(Comparator.comparing(LoginHistory::getLoginAt))
                                .orElse(null);
                        if (lastLogin != null) {
                            dto.setLastLoginIp(lastLogin.getIpAddress());
                            dto.setLastLoginAt(lastLogin.getLoginAt());
                        }
                        dto.setTotalLogins(history.size());
                    } else {
                        dto.setTotalLogins(0);
                    }

                    return dto;
                })
                .toList();

        return new  DataResponseMessage("Admin listesi başarıyla getirildi.",true, responses);
    }

    /*
    @Override
    public ResponseMessage resetAdminPassword(String username, Long adminId) {

        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        String newPassword = UUID.randomUUID().toString().substring(0, 8); // 8 karakterlik random şifre
        admin.setPassword(passwordEncoder.encode(newPassword));
        adminRepository.save(admin);

        // audit kaydı (isteğe bağlı)
        auditLogService.logAction(username, "RESET_ADMIN_PASSWORD", "Admin: " + admin.getEmail());

        return ResponseMessage.success("Şifre başarıyla sıfırlandı. Yeni şifre: " + newPassword);
    }

    // ==============================================================
    // 2. OTURUM SONLANDIRMA
    // ==============================================================
    @Override
    public ResponseMessage terminateAdminSessions(String username, Long adminId) {

        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        sessionManager.terminateSessionsForUser(admin.getEmail()); // aktif tokenları iptal et

        auditLogService.logAction(username, "TERMINATE_ADMIN_SESSIONS", "Admin: " + admin.getEmail());

        return ResponseMessage.success("Adminin aktif oturumları başarıyla sonlandırıldı.");
    }


    @Override
    public ResponseMessage createBulkAdmins(String username, List<CreateAdminRequest> createRequests) {

        List<Admin> newAdmins = new ArrayList<>();

        for (CreateAdminRequest request : createRequests) {
            Admin admin = Admin.builder()
                    .profileInfo(ProfileInfo.builder()
                            .name(request.getName())
                            .surname(request.getSurname())
                            .email(request.getEmail())
                            .build())
                    .userNumber(request.getTelephone())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .roles(Collections.singleton(Role.ROLE_EMPTY))
                    .status(UserStatus.ACTIVE)
                    .superAdminApproved(true)
                    .registeredAt(LocalDateTime.now())
                    .build();

            newAdmins.add(admin);
        }

        adminRepository.saveAll(newAdmins);
        auditLogService.logAction(username, "BULK_CREATE_ADMINS", "Toplam " + newAdmins.size() + " admin eklendi.");

        return ResponseMessage.success(newAdmins.size() + " yeni admin başarıyla oluşturuldu.");
    }


    @Override
    public ResponseMessage deactivateMultipleAdmins(String username, List<Long> adminIds) {

        List<Admin> admins = adminRepository.findAllById(adminIds);

        for (Admin admin : admins) {
            admin.setStatus(AccountStatus.SUSPENDED);
        }

        adminRepository.saveAll(admins);
        auditLogService.logAction(username, "BULK_DEACTIVATE_ADMINS", "Devre dışı bırakılan: " + adminIds);

        return ResponseMessage.success(admins.size() + " admin devre dışı bırakıldı.");
    }


    @Override
    public ResponseMessage activateMultipleAdmins(String username, List<Long> adminIds) {

        List<Admin> admins = adminRepository.findAllById(adminIds);

        for (Admin admin : admins) {
            admin.setStatus(AccountStatus.ACTIVE);
        }

        adminRepository.saveAll(admins);
        auditLogService.logAction(username, "BULK_ACTIVATE_ADMINS", "Aktifleştirilen: " + adminIds);

        return ResponseMessage.success(admins.size() + " admin yeniden aktifleştirildi.");
    }


    @Override
    public ResponseMessage assignRolesToMultipleAdmins(String username, Long adminId, List<String> roles) {

        Admin admin = adminRepository.findById(adminId)
                .orElseThrow(AdminNotFoundException::new);

        // Enum’a uygun hale getir
        List<Role> assignedRoles = roles.stream()
                .map(r -> Role.valueOf(r.toUpperCase()))
                .toList();

        admin.setRoles(new HashSet<>(assignedRoles)); // eğer @ElementCollection varsa
        adminRepository.save(admin);

        auditLogService.logAction(username, "ASSIGN_ROLES_TO_ADMIN", "Admin: " + admin.getEmail() + " - Roles: " + roles);

        return ResponseMessage.success("Admin rolleri başarıyla güncellendi: " + roles);
    }

     */


}
