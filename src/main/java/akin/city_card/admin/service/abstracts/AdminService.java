package akin.city_card.admin.service.abstracts;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.VerificationCodeRequest;
import jakarta.validation.Valid;

public interface AdminService {
    ResponseMessage signUp(@Valid CreateAdminRequest adminRequest);


}
