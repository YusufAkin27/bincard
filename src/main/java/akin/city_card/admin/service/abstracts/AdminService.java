package akin.city_card.admin.service.abstracts;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.request.UpdateDeviceInfoRequest;
import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.AdminDTO;
import akin.city_card.admin.core.response.LoginHistoryDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.location.core.response.LocationDTO;
import akin.city_card.location.exceptions.NoLocationFoundException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.ChangePasswordRequest;
import akin.city_card.user.core.request.UpdateProfileRequest;
import akin.city_card.user.exceptions.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import java.util.List;

public interface AdminService {
    ResponseMessage signUp(@Valid CreateAdminRequest adminRequest, HttpServletRequest httpServletRequest) throws PhoneIsNotValidException, PhoneNumberAlreadyExistsException;


    ResponseMessage changePassword(@Valid ChangePasswordRequest request, String username) throws AdminNotFoundException, PasswordTooShortException, PasswordSameAsOldException, IncorrectCurrentPasswordException;

    ResponseMessage updateProfile(@Valid UpdateProfileRequest request, String username) throws AdminNotFoundException;

    ResponseMessage updateDeviceInfo(UpdateDeviceInfoRequest request, String username) throws AdminNotFoundException;

    LocationDTO getLocation(String username) throws AdminNotFoundException, NoLocationFoundException;

    ResponseMessage updateLocation(UpdateLocationRequest request, String username) throws AdminNotFoundException;

    DataResponseMessage<List<LoginHistoryDTO>> getLoginHistory(String username) throws AdminNotFoundException;

    DataResponseMessage<AdminDTO> getProfile(String username) throws AdminNotFoundException;
}
