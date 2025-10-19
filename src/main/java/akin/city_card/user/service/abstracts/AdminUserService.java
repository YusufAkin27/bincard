package akin.city_card.user.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.Role;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.exception.VerificationCodeStillValidException;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.request.PermanentDeleteRequest;
import akin.city_card.user.core.request.SuspendUserRequest;
import akin.city_card.user.core.request.UnsuspendUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.UserStatus;
import akin.city_card.wallet.exceptions.AdminOrSuperAdminNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface AdminUserService {

    PageDTO<CacheUserDTO> getAllUsers(Pageable pageable, String username, HttpServletRequest httpServletRequest) throws AdminNotFoundException;

    PageDTO<CacheUserDTO> searchUsers(String name, Pageable pageable, String username, HttpServletRequest httpServletRequest) throws AdminNotFoundException;

    ResponseMessage bulkUpdateUserStatus(List<Long> userIds, UserStatus newStatus, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException;

    ResponseMessage bulkDeleteUsers(List<Long> userIds, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException;

    CacheUserDTO getUserById(Long userId, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminOrSuperAdminNotFoundException;

    Map<String, Object> getUserDeviceInfo(Long userId, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminNotFoundException;

    ResponseMessage assignRolesToUser(Long userId, Set<Role> roles, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException;

    ResponseMessage removeRolesFromUser(Long userId, Set<Role> roles, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException;

    ResponseMessage bulkAssignRoles(List<Long> userIds, Set<Role> roles, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminNotFoundException;

    ResponseMessage resetUserPassword(Long userId, String newPassword, String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, AdminNotFoundException;


    ResponseMessage updateEmailVerificationStatus(Long userId, boolean verified, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException, UserNotFoundException;

    ResponseMessage updatePhoneVerificationStatus(Long userId, boolean verified, String username, HttpServletRequest httpServletRequest) throws AdminOrSuperAdminNotFoundException, UserNotFoundException;

    List<Map<String, Object>> getUserActiveSessions(Long userId, HttpServletRequest httpServletRequest);

    ResponseMessage terminateUserSession(Long userId, String sessionId, String username, HttpServletRequest httpServletRequest);


    ResponseMessage banIpAddress(String ipAddress, String reason, LocalDateTime expiresAt, String username);

    ResponseMessage suspendUser(String username, Long userId, SuspendUserRequest request);

    ResponseMessage permanentlyDeleteUser(String username, Long userId, PermanentDeleteRequest request);

    ResponseMessage unsuspendUser(String username, Long userId, UnsuspendUserRequest request);

    ResponseMessage banUserDevice(Long userId, String deviceId, String reason, String username);

    Page<Map<String, Object>> getSuspiciousActivities(String startDate, String endDate, String activityType, Pageable pageable);

    Page<Map<String, Object>> getUserAuditLogs(Long userId, String startDate, String endDate, String action, Pageable pageable);

    Map<String, Object> getUserStatistics();

    List<ResponseMessage> createAll(String username, @Valid List<CreateUserRequest> createUserRequests, HttpServletRequest httpServletRequest) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException, VerificationCodeStillValidException, AdminOrSuperAdminNotFoundException;

    Page<LoginHistory> getUserLoginHistory(Long userId, String startDate, String endDate, Pageable pageable);

    Page<SearchHistoryDTO> getUserSearchHistory(Long userId, String startDate, String endDate, Pageable pageable);

    ResponseMessage sendNotificationToUser(Long userId, String title, String message, String type, String username) throws UserNotFoundException;

    ResponseMessage sendBulkNotification(List<Long> userIds, String title, String message, String type, String username);


    void exportUsersToExcel(List<Long> userIds, UserStatus status, Role role, HttpServletResponse response, String username);


    Map<String, Object> getUserBehaviorAnalysis(Long userId, int days);

    byte[] generateUserDataPdf(Long userId) throws UserNotFoundException;

    void sendUserDataPdfByEmail(Long userId, String email) throws UserNotFoundException;
}
