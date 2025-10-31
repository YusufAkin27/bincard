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
import akin.city_card.user.core.response.Views;
import akin.city_card.user.exceptions.*;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateAdminRequest adminRequest,
                                  HttpServletRequest httpServletRequest)
            throws PhoneNumberAlreadyExistsException,
            PhoneIsNotValidException {
        return adminService.signUp(adminRequest, httpServletRequest);
    }

    @PutMapping("/change-password")
    public ResponseMessage changePassword(@AuthenticationPrincipal UserDetails userDetails, @Valid @RequestBody ChangePasswordRequest request) throws IncorrectCurrentPasswordException, PasswordSameAsOldException, AdminNotFoundException, PasswordTooShortException {
        return adminService.changePassword(request, userDetails.getUsername());
    }

    @GetMapping("/profile")
    public DataResponseMessage<AdminDTO> getProfile(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException {
        return adminService.getProfile(userDetails.getUsername());
    }

    @PutMapping("/update-profile")
    public ResponseMessage updateProfile(@AuthenticationPrincipal UserDetails userDetails, @Valid @RequestBody UpdateProfileRequest request) throws AdminNotFoundException {
        return adminService.updateProfile(request, userDetails.getUsername());
    }

    @PutMapping("/update-device-info")
    public ResponseMessage updateDeviceInfo(@AuthenticationPrincipal UserDetails userDetails, @RequestBody UpdateDeviceInfoRequest request) throws AdminNotFoundException {
        return adminService.updateDeviceInfo(request, userDetails.getUsername());
    }

    // 4. Konum & Oturum Bilgileri
    @GetMapping("/location")
    public LocationDTO getLocation(@AuthenticationPrincipal UserDetails userDetails) throws AdminNotFoundException, NoLocationFoundException {
        return adminService.getLocation(userDetails.getUsername());
    }

    @PutMapping("/location")
    public ResponseMessage updateLocation(@AuthenticationPrincipal UserDetails userDetails, @RequestBody @Valid UpdateLocationRequest request) throws AdminNotFoundException {
        return adminService.updateLocation(request, userDetails.getUsername());
    }

    @GetMapping("/login-history")
    public DataResponseMessage<Page<LoginHistoryDTO>> getLoginHistory(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id,desc") String sort) throws AdminNotFoundException {

        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 && sortParams[1].equalsIgnoreCase("asc")
                ? Sort.Direction.ASC
                : Sort.Direction.DESC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));
        return adminService.getLoginHistory(userDetails.getUsername(), pageable);
    }
    @GetMapping("/audit-logs")
    public DataResponseMessage<Page<AuditLogDTO>> getAuditLogs(
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate,
            @RequestParam(required = false) String action,
            @AuthenticationPrincipal UserDetails userDetails) {
        return adminService.getAuditLogs(fromDate, toDate, action, userDetails.getUsername());
    }


}
