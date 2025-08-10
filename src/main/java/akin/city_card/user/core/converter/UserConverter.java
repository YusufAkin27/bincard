package akin.city_card.user.core.converter;

import akin.city_card.geoAlert.core.response.GeoAlertDTO;
import akin.city_card.geoAlert.model.GeoAlert;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.*;
import akin.city_card.user.model.*;

public interface UserConverter {

    User convertUserToCreateUser(CreateUserRequest createUserRequest);
    SearchHistoryDTO toDto(SearchHistory sh);
    CacheUserDTO toCacheUserDTO(User user);

    SearchHistoryDTO toSearchHistoryDTO(SearchHistory searchHistory);
    UserIdentityInfoDTO toUserIdentityInfoDTO(UserIdentityInfo entity);
    IdentityVerificationRequestDTO convertToVerificationRequestDTO(IdentityVerificationRequest entity);

}
