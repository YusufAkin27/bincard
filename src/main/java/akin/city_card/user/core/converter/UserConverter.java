package akin.city_card.user.core.converter;

import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.IdentityVerificationRequestDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.core.response.UserIdentityInfoDTO;
import akin.city_card.user.model.IdentityVerificationRequest;
import akin.city_card.user.model.SearchHistory;
import akin.city_card.user.model.User;
import akin.city_card.user.model.UserIdentityInfo;

public interface UserConverter {

    User convertUserToCreateUser(CreateUserRequest createUserRequest);

    SearchHistoryDTO toDto(SearchHistory sh);

    CacheUserDTO toCacheUserDTO(User user);

    SearchHistoryDTO toSearchHistoryDTO(SearchHistory searchHistory);

    UserIdentityInfoDTO toUserIdentityInfoDTO(UserIdentityInfo entity);

    IdentityVerificationRequestDTO convertToVerificationRequestDTO(IdentityVerificationRequest entity);

}
