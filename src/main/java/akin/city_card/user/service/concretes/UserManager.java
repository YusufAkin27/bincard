package akin.city_card.user.service.concretes;

import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.wallet.model.Currency;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletStatus;
import akin.city_card.wallet.repository.WalletRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.beans.Transient;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class UserManager implements UserService {
    private final UserRepository userRepository;
    private final UserConverter userConverter;
    private final WalletRepository walletRepository;


    @Override
    @Transactional
    public ResponseMessage create(CreateUserRequest request) {
        // Telefon format kontrolü
        if (request.getTelephone() == null || !request.getTelephone().matches("^\\+90\\d{10}$")) {
            return new ResponseMessage("Telefon numarası +90 ile başlayıp, ardından 10 rakamdan oluşmalıdır.", false);
        }

        // Şifre format kontrolü
        if (request.getPassword() == null || !request.getPassword().matches("^\\d{6}$")) {
            return new ResponseMessage("Şifre 6 rakamdan oluşmalıdır.", false);
        }

        // Telefon numarası zaten var mı?
        if (userRepository.existsByUserNumber(request.getTelephone())) {
            return new ResponseMessage("Bu telefon numarası zaten kayıtlı.", false);
        }

        User user = userConverter.convertUserToCreateUser(request);
        userRepository.save(user);

        // Eğer özel bilgiler girilmişse, cüzdan oluştur ve kullanıcıya bağla
        if (user.getNationalId() != null && user.getBirthDate() != null) {
            user.setWalletActivated(true); // Flag işaretleniyor
            Random random = new Random();
            int value = random.nextInt(1001); // 0 ile 1000 arasında tam sayı
            BigDecimal bigDecimal = BigDecimal.valueOf(value);            Wallet wallet = Wallet.builder()
                    .user(user)
                    .currency(Currency.TRY)
                    .balance(bigDecimal)
                    .status(WalletStatus.ACTIVE)
                    .build();

            user.setWallet(wallet);
            walletRepository.save(wallet);
        }


        return new ResponseMessage("Kullanıcı başarıyla oluşturuldu.", true);
    }


    @Override
    public UserDTO getProfile(String username) {
        return null;
    }

    @Override
    public ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest) {
        return null;
    }


    @Override
    public ResponseMessage verifyPhone(String username, VerifyPhoneRequest request) {
        return null;
    }

    @Override
    public ResponseMessage deactivateUser(String username) {
        return null;
    }

    @Override
    public List<ResponseMessage> createAll(List<CreateUserRequest> createUserRequests) {
        List<ResponseMessage> responseMessages = new ArrayList<>();
        for (CreateUserRequest createUserRequest : createUserRequests) {
            responseMessages.add(create(createUserRequest));
        }

        return responseMessages;

    }

}
