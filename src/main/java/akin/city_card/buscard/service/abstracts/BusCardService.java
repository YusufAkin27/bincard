package akin.city_card.buscard.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.buscard.core.request.CreateCardPricingRequest;
import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.buscard.core.request.UpdateCardPricingRequest;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.CardPricingNotFoundException;
import akin.city_card.buscard.exceptions.ExpiredQrCodeException;
import akin.city_card.buscard.exceptions.InvalidQrCodeException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

public interface BusCardService {
    ResponseEntity<?> registerCard(RegisterCardRequest req);

    ResponseEntity<?> readCard(String uid);

    ResponseEntity<?> topUpBalance(String uid, BigDecimal bigDecimal);

    ResponseEntity<?> getOn(String uid);

    ResponseMessage createCardPricing(CreateCardPricingRequest createCardPricingRequest, String username) throws AdminNotFoundException;

    ResponseEntity<?> cardVisa(Map<String, Object> request);

    ResponseEntity<?> deleteCardBlocked(Map<String, String> request);

    ResponseEntity<?> cardBlocked(Map<String, Object> request);

    byte[] generateQrCode(String username) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException, CardPricingNotFoundException, InsufficientBalanceException;

    ResponseMessage verifyQrToken(String qrToken) throws InvalidQrCodeException, ExpiredQrCodeException, UserNotFoundException, WalletNotFoundException, InsufficientBalanceException;

    List<CardPricingDTO> getAllCardPricing();

    ResponseMessage updateCardPricing(String username, UpdateCardPricingRequest updateCardPricingRequest) throws AdminNotFoundException, CardPricingNotFoundException;


}
