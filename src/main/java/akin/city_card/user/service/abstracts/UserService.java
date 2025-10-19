package akin.city_card.user.service.abstracts;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.buscard.core.request.FavoriteCardRequest;
import akin.city_card.buscard.core.response.FavoriteBusCardDTO;
import akin.city_card.buscard.exceptions.BusCardNotFoundException;
import akin.city_card.notification.core.request.NotificationPreferencesDTO;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.*;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.exceptions.*;
import akin.city_card.verification.exceptions.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface UserService {

    ResponseMessage create(CreateUserRequest createUserRequest, HttpServletRequest request) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException, VerificationCodeStillValidException;

    CacheUserDTO getProfile(String username, HttpServletRequest httpServletRequest) throws UserNotFoundException;

    ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest, HttpServletRequest httpServletRequest) throws UserNotFoundException, EmailAlreadyExistsException;

    ResponseMessage updateProfilePhoto(String username, MultipartFile file, HttpServletRequest httpServletRequest) throws PhotoSizeLargerException, IOException, UserNotFoundException;

    ResponseMessage verifyPhone(VerificationCodeRequest request, HttpServletRequest httpServletRequest) throws UserNotFoundException, VerificationCodeNotFoundException, UsedVerificationCodeException, CancelledVerificationCodeException, VerificationCodeExpiredException;

    ResponseMessage sendPasswordResetCode(String phone, HttpServletRequest httpServletRequest) throws UserNotFoundException;

    ResponseMessage resetPassword(PasswordResetRequest request, HttpServletRequest httpServletRequest) throws PasswordResetTokenNotFoundException, PasswordResetTokenExpiredException, PasswordResetTokenIsUsedException, PasswordTooShortException, SamePasswordException;

    ResponseMessage changePassword(String username, ChangePasswordRequest request, HttpServletRequest httpServletRequest) throws UserIsDeletedException, UserNotActiveException, UserNotFoundException, PasswordsDoNotMatchException, InvalidNewPasswordException, IncorrectCurrentPasswordException, SamePasswordException;

    ResponseMessage resendPhoneVerificationCode(ResendPhoneVerificationRequest request) throws UserNotFoundException;

    ResponseMessage verifyPhoneForPasswordReset(VerificationCodeRequest verificationCodeRequest) throws InvalidOrUsedVerificationCodeException, VerificationCodeExpiredException;

    boolean updateFCMToken(String fcmToken, String username) throws UserNotFoundException;

    List<FavoriteBusCardDTO> getFavoriteCards(String username) throws UserNotFoundException;

    ResponseMessage addFavoriteCard(String username, FavoriteCardRequest request) throws UserNotFoundException;

    ResponseMessage removeFavoriteCard(String username, Long cardId) throws UserNotFoundException;


    CacheUserDTO updateNotificationPreferences(String username, NotificationPreferencesDTO preferences) throws UserNotFoundException;


    ResponseMessage setLowBalanceThreshold(String username, LowBalanceAlertRequest request) throws UserNotFoundException, BusCardNotFoundException, AlreadyBusCardLowBalanceException;

    List<SearchHistoryDTO> getSearchHistory(String username) throws UserNotFoundException;

    ResponseMessage clearSearchHistory(String username) throws UserNotFoundException;


    Page<AuditLogDTO> getUserActivityLog(String username, Pageable pageable) throws UserNotFoundException;

    ResponseMessage deleteProfilePhoto(String username) throws UserNotFoundException;

    void updateLocation(String username, @Valid UpdateLocationRequest updateLocationRequest) throws UserNotFoundException;

    ResponseMessage verifyEmail(String token, String email, HttpServletRequest request) throws VerificationCodeNotFoundException, VerificationCodeExpiredException, VerificationCodeStillValidException, UserNotFoundException, VerificationCodeAlreadyUsedException, VerificationCodeCancelledException, VerificationCodeTypeMismatchException, EmailMismatchException, InvalidVerificationCodeException;

    ResponseMessage deleteAccount(String username, DeleteAccountRequest request, HttpServletRequest httpRequest) throws ApproveIsConfirmDeletionException, UserNotFoundException, PasswordsDoNotMatchException, WalletBalanceNotZeroException;

    ResponseMessage freezeAccount(String username, FreezeAccountRequest request, HttpServletRequest httpRequest) throws UserNotFoundException;


}
