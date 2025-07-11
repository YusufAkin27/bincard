package akin.city_card.redis;

import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CachedUserLookupService {
    private final UserRepository  userRepository;
    private final UserConverter userConverter;

    @Cacheable(value = "users", key = "#username")
    public CacheUserDTO findByUsername(String username) throws UserNotFoundException {
        System.out.println("Veritabanından çağrılıyor ve cache'e eklenecek: " + username);
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        if (user == null) {
            throw new UserNotFoundException();
        }
        return userConverter.toCacheUserDTO(user);
    }


}
