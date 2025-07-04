package akin.city_card.user.service.abstracts;

import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotActiveException;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.exception.VerificationCodeStillValidException;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.exceptions.*;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import akin.city_card.verification.exceptions.InvalidOrUsedVerificationCodeException;
import jakarta.validation.Valid;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

public interface UserService {

    ResponseMessage create(CreateUserRequest createUserRequest) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException, VerificationCodeStillValidException;

    UserDTO getProfile(String username) throws UserNotFoundException;

    ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest) throws UserNotFoundException;


    ResponseMessage deactivateUser(String username) throws UserNotFoundException;

    List<ResponseMessage> createAll(@Valid List<CreateUserRequest> createUserRequests) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException, VerificationCodeStillValidException;

    ResponseMessage updateProfilePhoto(String username, MultipartFile file) throws PhotoSizeLargerException, IOException, UserNotFoundException;

    ResponseMessage verifyPhone( VerificationCodeRequest request) throws UserNotFoundException;


    ResponseMessage sendPasswordResetCode(String phone) throws UserNotFoundException;

    ResponseMessage resetPassword(PasswordResetRequest request) throws PasswordResetTokenNotFoundException, PasswordResetTokenExpiredException, PasswordResetTokenIsUsedException, PasswordTooShortException, SamePasswordException;

    ResponseMessage changePassword(String username, ChangePasswordRequest request) throws UserIsDeletedException, UserNotActiveException, UserNotFoundException, PasswordsDoNotMatchException, InvalidNewPasswordException, IncorrectCurrentPasswordException, SamePasswordException;


    ResponseMessage resendPhoneVerificationCode(ResendPhoneVerificationRequest request) throws UserNotFoundException;

    ResponseMessage verifyPhoneForPasswordReset(VerificationCodeRequest verificationCodeRequest) throws InvalidOrUsedVerificationCodeException, ExpiredVerificationCodeException;
}
