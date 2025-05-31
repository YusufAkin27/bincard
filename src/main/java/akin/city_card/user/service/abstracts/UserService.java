package akin.city_card.user.service.abstracts;

import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.CreateUserRequest;

public interface UserService {

    ResponseMessage create(CreateUserRequest createUserRequest);
}
