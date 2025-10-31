package akin.city_card.buscard.service.abstracts;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.buscard.core.request.*;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.*;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.wallet.core.request.TopUpBalanceRequest;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface BusCardService {
    BusCardDTO registerCard(HttpServletRequest httpServletRequest, RegisterCardRequest req, String username) throws AlreadyBusCardNumberException;

    BusCardDTO readCard(String reqUid, String username) throws BusCardNotFoundException;


    BusCardDTO getOn(GetOnBusRequest request) throws InsufficientBalanceException, CardInactiveException, CardPricingNotFoundException, CorruptedDataException, SubscriptionNotFoundException, SubscriptionExpiredException, BusNotFoundException;

    ResponseMessage createCardPricing(CreateCardPricingRequest createCardPricingRequest, String username) throws AdminNotFoundException;

    BusCardDTO cardVisa(ReadCardRequest request, String username) throws BusCardNotFoundException, AdminNotFoundException, BusCardNotStudentException, BusCardNotActiveException;


    BusCardDTO cardBlocked(ReadCardRequest request, String username) throws AdminNotFoundException, BusCardNotActiveException, BusCardNotFoundException, BusCardAlreadyIsBlockedException;

    byte[] generateQrCode(String username) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException, CardPricingNotFoundException, InsufficientBalanceException;

    ResponseMessage verifyQrToken(String qrToken) throws InvalidQrCodeException, ExpiredQrCodeException, UserNotFoundException, WalletNotFoundException, InsufficientBalanceException, WalletNotActiveException, CardPricingNotFoundException;

    List<CardPricingDTO> getAllCardPricing();

    ResponseMessage updateCardPricing(String username, UpdateCardPricingRequest updateCardPricingRequest) throws AdminNotFoundException, CardPricingNotFoundException;


    BusCardDTO deleteCardBlocked(ReadCardRequest request, String username) throws BusCardNotFoundException, AdminNotFoundException, BusCardNotActiveException, BusCardAlreadyIsBlockedException, BusCardNotBlockedException;

    List<BusCardDTO> getBlockedCards(String username);

    BusCardDTO topUpBalance(String username, TopUpBalanceCardRequest request) throws TransactionCounterException, BusCardNotFoundException, BusCardNotActiveException, AdminNotFoundException;

    BusCardDTO editCard(String username, UpdateBusCardRequest updateCardRequest) throws BusCardNotFoundException;

    ResponseMessage deleteCard(String username, ReadCardRequest deleteCardRequest) throws AdminNotFoundException, BusCardNotFoundException;

    BusCardDTO abonmanOluştur(CreateSubscriptionRequest createSubscriptionRequest, String username) throws BusCardNotFoundException, AdminNotFoundException;

    Page<BusCardDTO> getAllCards(String username, Pageable pageable) throws AdminNotFoundException;

    boolean qrStatus(String token);

    ResponseEntity<String> complete3DPayment(String paymentId, String conversationId, HttpServletRequest httpServletRequest);

    ResponseMessage topUp(String username, String cardNumber, @Valid TopUpBalanceRequest topUpBalanceRequest) throws BusCardNotFoundException, BusCardNotActiveException, BusCardIsBlockedException, MinumumTopUpAmountException, UserNotFoundException;

    // Login olmadan kart numarasıyla 3D top-up başlatma
    ResponseMessage topUpAsGuest(String cardNumber, @Valid TopUpBalanceRequest topUpBalanceRequest) throws BusCardNotFoundException, BusCardNotActiveException, BusCardIsBlockedException, MinumumTopUpAmountException;

    BusCardDTO balanceInquiry(String cardNumber) throws BusCardNotFoundException;

    ResponseMessage topUpUsingWallet(String username, @Valid TopUpCardRequest topUpCardRequest, HttpServletRequest httpServletRequest) throws BusCardIsBlockedException, BusCardNotActiveException, MinumumTopUpAmountException, InsufficientBalanceException, UserNotFoundException, BusCardNotFoundException, WalletNotFoundException;
    //aa
}
