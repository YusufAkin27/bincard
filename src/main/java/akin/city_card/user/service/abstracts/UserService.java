package akin.city_card.user.service.abstracts;

import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import jakarta.validation.Valid;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface UserService {

    ResponseMessage create(CreateUserRequest createUserRequest) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException;

    UserDTO getProfile(String username) throws UserNotFoundException;

    ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest) throws UserNotFoundException;


    ResponseMessage deactivateUser(String username) throws UserNotFoundException;

    List<ResponseMessage> createAll(@Valid List<CreateUserRequest> createUserRequests) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException;

    ResponseMessage updateProfilePhoto(String username, MultipartFile file) throws PhotoSizeLargerException, IOException, UserNotFoundException;

    ResponseMessage verifyPhone( VerificationCodeRequest request) throws UserNotFoundException;

    ResponseMessage sendEmailVerificationLink(String username);

    ResponseMessage verifyEmail(String token);

    ResponseMessage sendPasswordResetCode(String emailOrPhone);

    ResponseMessage resetPassword(PasswordResetRequest request);

    ResponseMessage changePassword(String username, ChangePasswordRequest request);

    ResponseMessage enableTwoFactor(String username) throws UserNotFoundException;

    ResponseMessage disableTwoFactor(String username) throws UserNotFoundException;

    ResponseMessage resendPhoneVerificationCode(ResendPhoneVerificationRequest request) throws UserNotFoundException;

    ResponseMessage resendEmailVerificationLink(String email);
}
