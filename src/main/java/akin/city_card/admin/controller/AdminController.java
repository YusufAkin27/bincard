package akin.city_card.admin.controller;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.request.UpdateDeviceInfoRequest;
import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.AdminDTO;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.core.response.LoginHistoryDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.service.abstracts.AdminService;
import akin.city_card.location.core.response.LocationDTO;
import akin.city_card.location.exceptions.NoLocationFoundException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.ChangePasswordRequest;
import akin.city_card.user.core.request.UpdateProfileRequest;
import akin.city_card.user.exceptions.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminController {

    private final AdminService adminService;

    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateAdminRequest adminRequest,
                                  HttpServletRequest httpServletRequest)
            throws PhoneNumberAlreadyExistsException,
            PhoneIsNotValidException {
        log.debug("AdminController.signUp - Method called with telephone: {}", adminRequest.getTelephone());
        try {
            ResponseMessage response = adminService.signUp(adminRequest, httpServletRequest);
            log.info("AdminController.signUp - Success for telephone: {}", adminRequest.getTelephone());
            return response;
        } catch (PhoneNumberAlreadyExistsException | PhoneIsNotValidException e) {
            log.error("AdminController.signUp - Error for telephone: {}, Error: {}", adminRequest.getTelephone(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.signUp - Unexpected error for telephone: {}", adminRequest.getTelephone(), e);
            throw e;
        }
    }

    @PutMapping("/change-password")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public ResponseMessage changePassword(@AuthenticationPrincipal UserDetails userDetails, @Valid @RequestBody ChangePasswordRequest request) throws IncorrectCurrentPasswordException, PasswordSameAsOldException, AdminNotFoundException, PasswordTooShortException {
        log.debug("AdminController.changePassword - Method called for user: {}", userDetails.getUsername());
        try {
            ResponseMessage response = adminService.changePassword(request, userDetails.getUsername());
            log.info("AdminController.changePassword - Success for user: {}", userDetails.getUsername());
            return response;
        } catch (IncorrectCurrentPasswordException | PasswordSameAsOldException | AdminNotFoundException | PasswordTooShortException e) {
            log.error("AdminController.changePassword - Error for user: {}, Error: {}", userDetails.getUsername(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.changePassword - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

    @GetMapping("/profile")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public DataResponseMessage<AdminDTO> getProfile(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException {
        log.debug("AdminController.getProfile - Method called for user: {}", userDetails.getUsername());
        try {
            DataResponseMessage<AdminDTO> response = adminService.getProfile(userDetails.getUsername());
            log.info("AdminController.getProfile - Success for user: {}", userDetails.getUsername());
            return response;
        } catch (AdminNotFoundException e) {
            log.error("AdminController.getProfile - Admin not found: {}", userDetails.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.getProfile - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

    @PutMapping("/update-profile")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public ResponseMessage updateProfile(@AuthenticationPrincipal UserDetails userDetails, @Valid @RequestBody UpdateProfileRequest request) throws AdminNotFoundException {
        log.debug("AdminController.updateProfile - Method called for user: {}, Request: name={}, surname={}, email={}", 
                userDetails.getUsername(), request.getName(), request.getSurname(), request.getEmail());
        try {
            ResponseMessage response = adminService.updateProfile(request, userDetails.getUsername());
            log.info("AdminController.updateProfile - Success for user: {}", userDetails.getUsername());
            return response;
        } catch (AdminNotFoundException e) {
            log.error("AdminController.updateProfile - Admin not found: {}", userDetails.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.updateProfile - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

    @PutMapping("/update-device-info")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public ResponseMessage updateDeviceInfo(@AuthenticationPrincipal UserDetails userDetails, @RequestBody UpdateDeviceInfoRequest request) throws AdminNotFoundException {
        log.debug("AdminController.updateDeviceInfo - Method called for user: {}, IP: {}, FCM: {}", 
                userDetails.getUsername(), request.getIpAddress(), request.getFcmToken() != null ? "provided" : "not provided");
        try {
            ResponseMessage response = adminService.updateDeviceInfo(request, userDetails.getUsername());
            log.info("AdminController.updateDeviceInfo - Success for user: {}", userDetails.getUsername());
            return response;
        } catch (AdminNotFoundException e) {
            log.error("AdminController.updateDeviceInfo - Admin not found: {}", userDetails.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.updateDeviceInfo - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

    // 4. Konum & Oturum Bilgileri
    @GetMapping("/location")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public LocationDTO getLocation(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException, NoLocationFoundException {
        log.debug("AdminController.getLocation - Method called for user: {}", userDetails.getUsername());
        try {
            LocationDTO response = adminService.getLocation(userDetails.getUsername());
            log.info("AdminController.getLocation - Success for user: {}", userDetails.getUsername());
            return response;
        } catch (AdminNotFoundException | NoLocationFoundException e) {
            log.error("AdminController.getLocation - Error for user: {}, Error: {}", userDetails.getUsername(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.getLocation - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

    @PutMapping("/location")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public ResponseMessage updateLocation(@AuthenticationPrincipal UserDetails userDetails, @RequestBody @Valid UpdateLocationRequest request) throws AdminNotFoundException {
        log.debug("AdminController.updateLocation - Method called for user: {}, Lat: {}, Lon: {}", 
                userDetails.getUsername(), request.getLatitude(), request.getLongitude());
        try {
            ResponseMessage response = adminService.updateLocation(request, userDetails.getUsername());
            log.info("AdminController.updateLocation - Success for user: {}", userDetails.getUsername());
            return response;
        } catch (AdminNotFoundException e) {
            log.error("AdminController.updateLocation - Admin not found: {}", userDetails.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.updateLocation - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

    @GetMapping("/login-history")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public DataResponseMessage<Page<LoginHistoryDTO>> getLoginHistory(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id,desc") String sort) throws AdminNotFoundException {
        log.debug("AdminController.getLoginHistory - Method called for user: {}, Page: {}, Size: {}, Sort: {}", 
                userDetails.getUsername(), page, size, sort);
        try {
            String[] sortParams = sort.split(",");
            Sort.Direction direction = sortParams.length > 1 && sortParams[1].equalsIgnoreCase("asc")
                    ? Sort.Direction.ASC
                    : Sort.Direction.DESC;

            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));
            DataResponseMessage<Page<LoginHistoryDTO>> response = adminService.getLoginHistory(userDetails.getUsername(), pageable);
            log.info("AdminController.getLoginHistory - Success for user: {}, Total elements: {}", 
                    userDetails.getUsername(), response.getData() != null ? response.getData().getTotalElements() : 0);
            return response;
        } catch (AdminNotFoundException e) {
            log.error("AdminController.getLoginHistory - Admin not found: {}", userDetails.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.getLoginHistory - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }
    @GetMapping("/audit-logs")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public DataResponseMessage<Page<AuditLogDTO>> getAuditLogs(
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate,
            @RequestParam(required = false) String action,
            @AuthenticationPrincipal UserDetails userDetails) {
        log.debug("AdminController.getAuditLogs - Method called for user: {}, FromDate: {}, ToDate: {}, Action: {}", 
                userDetails.getUsername(), fromDate, toDate, action);
        try {
            DataResponseMessage<Page<AuditLogDTO>> response = adminService.getAuditLogs(fromDate, toDate, action, userDetails.getUsername());
            log.info("AdminController.getAuditLogs - Success for user: {}, Total elements: {}", 
                    userDetails.getUsername(), response.getData() != null ? response.getData().getTotalElements() : 0);
            return response;
        } catch (Exception e) {
            log.error("AdminController.getAuditLogs - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAnyAuthority('ADMIN_ALL', 'USER_ADMIN', 'WALLET_ADMIN', 'REPORT_ADMIN', 'CONTRACT_ADMIN', 'PAYMENT_POINT_ADMIN', 'BUS_ADMIN', 'BUS_CARD_ADMIN', 'ROUTE_ADMIN', 'STATION_ADMIN', 'DRIVER_ADMIN', 'NEWS_ADMIN', 'AUTO_TOP_UP_ADMIN', 'FEED_BACK_ADMIN', 'GEO_ALERT_ADMIN', 'HEALTH_ADMIN', 'LOCATION_ADMIN', 'NOTIFICATION_ADMIN', 'SCHEDULE_ADMIN', 'CARD_VISA_ADMIN', 'SUPERADMIN')")
    public DataResponseMessage<List<String>> getMyRoles(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException {
        log.debug("AdminController.getMyRoles - Method called for user: {}", userDetails.getUsername());
        try {
            DataResponseMessage<List<String>> response = adminService.getMyRoles(userDetails.getUsername());
            log.info("AdminController.getMyRoles - Success for user: {}, Roles count: {}", 
                    userDetails.getUsername(), response.getData() != null ? response.getData().size() : 0);
            return response;
        } catch (AdminNotFoundException e) {
            log.error("AdminController.getMyRoles - Admin not found: {}", userDetails.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("AdminController.getMyRoles - Unexpected error for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }

}
