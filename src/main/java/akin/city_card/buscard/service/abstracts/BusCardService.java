package akin.city_card.buscard.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.buscard.core.request.CreateCardPricingRequest;
import akin.city_card.buscard.core.request.ReadCardRequest;
import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.buscard.core.request.UpdateCardPricingRequest;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.CardPricingNotFoundException;
import akin.city_card.buscard.exceptions.ExpiredQrCodeException;
import akin.city_card.buscard.exceptions.InvalidQrCodeException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

public interface BusCardService {
    BusCardDTO registerCard(RegisterCardRequest req, String username);

    BusCardDTO readCard(String reqUid, String uid);

    BusCardDTO topUpBalance(String username, String uid, BigDecimal bigDecimal);

    BusCardDTO getOn(String uid);

    ResponseMessage createCardPricing(CreateCardPricingRequest createCardPricingRequest, String username) throws AdminNotFoundException;

    BusCardDTO cardVisa(ReadCardRequest request, String username);

    BusCardDTO deleteCardBlocked(Map<String, String> request);

    BusCardDTO cardBlocked(Map<String, Object> request);

    byte[] generateQrCode(String username) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException, CardPricingNotFoundException, InsufficientBalanceException;

    ResponseMessage verifyQrToken(String qrToken) throws InvalidQrCodeException, ExpiredQrCodeException, UserNotFoundException, WalletNotFoundException, InsufficientBalanceException;

    List<CardPricingDTO> getAllCardPricing();

    ResponseMessage updateCardPricing(String username, UpdateCardPricingRequest updateCardPricingRequest) throws AdminNotFoundException, CardPricingNotFoundException;


}
