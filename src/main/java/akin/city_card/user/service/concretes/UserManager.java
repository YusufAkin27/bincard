package akin.city_card.user.service.concretes;

import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.abstracts.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserManager implements UserService {
    private final UserRepository userRepository;
    private final UserConverter userConverter;



    @Override
    public ResponseMessage create(CreateUserRequest request) {
        // 1. Alanların boş olup olmadığını kontrol et
        if (request.getFirstName() == null || request.getFirstName().trim().isEmpty()) {
            return new ResponseMessage( "İsim boş olamaz.",false);
        }

        if (request.getLastName() == null || request.getLastName().trim().isEmpty()) {
            return new ResponseMessage( "Soyisim boş olamaz.",false);
        }

        // 2. Telefon numarası formatını kontrol et (örnek: sadece 10 haneli rakamlar)
        String phoneRegex = "^\\d{10}$"; // 05xx xxx xxxx gibi değilse
        if (!request.getTelephone().matches(phoneRegex)) {
            return new ResponseMessage( "Telefon numarası geçerli değil. Sadece 10 haneli rakam girin.",false);
        }

        // 3. Telefon numarası benzersiz mi?
        if (userRepository.existsByUserNumber(request.getTelephone())) {
            return new ResponseMessage( "Bu telefon numarası zaten kayıtlı.",false);
        }

        // 4. Şifre uzunluğu en az 6 karakter mi?
        if (request.getPassword() == null || request.getPassword().length() < 6) {
            return new ResponseMessage( "Şifre en az 6 karakter olmalıdır.",false);
        }

        // 5. Dönüştür ve kaydet
        User user = userConverter.convertUserToCreateUser(request);
        userRepository.save(user);

        return new ResponseMessage( "Kullanıcı başarıyla oluşturuldu.",true);
    }

}
