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
import com.iyzipay.request.DeleteCardRequest;
import io.craftgate.request.UpdateCardRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface BusCardService {
    BusCardDTO registerCard(HttpServletRequest httpServletRequest, RegisterCardRequest req, String username) throws AlreadyBusCardNumberException;

    BusCardDTO readCard(String reqUid, String username) throws BusCardNotFoundException;


    BusCardDTO getOn(GetOnBusRequest request) throws InsufficientBalanceException, BusCardNotFoundException, CardInactiveException, CardPricingNotFoundException, CorruptedDataException, SubscriptionNotFoundException, SubscriptionExpiredException;

    ResponseMessage createCardPricing(CreateCardPricingRequest createCardPricingRequest, String username) throws AdminNotFoundException;

    BusCardDTO cardVisa(ReadCardRequest request, String username) throws BusCardNotFoundException, AdminNotFoundException, BusCardNotStudentException, BusCardNotActiveException;


    BusCardDTO cardBlocked(ReadCardRequest request, String username) throws AdminNotFoundException, BusCardNotActiveException, BusCardNotFoundException, BusCardAlreadyIsBlockedException;

    byte[] generateQrCode(String username) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException, CardPricingNotFoundException, InsufficientBalanceException;

    ResponseMessage verifyQrToken(String qrToken) throws InvalidQrCodeException, ExpiredQrCodeException, UserNotFoundException, WalletNotFoundException, InsufficientBalanceException, WalletNotActiveException, CardPricingNotFoundException;

    List<CardPricingDTO> getAllCardPricing();

    ResponseMessage updateCardPricing(String username, UpdateCardPricingRequest updateCardPricingRequest) throws AdminNotFoundException, CardPricingNotFoundException;


    BusCardDTO deleteCardBlocked(ReadCardRequest request, String username) throws BusCardNotFoundException, AdminNotFoundException, BusCardNotActiveException, BusCardAlreadyIsBlockedException, BusCardNotBlockedException;

    List<BusCardDTO> getBlockedCards(String username);

    BusCardDTO topUpBalance(String username, TopUpBalanceCardRequest request) throws TransactionCounterException, BusCardNotFoundException, BusCardNotActiveException;

    BusCardDTO editCard(String username, UpdateCardRequest updateCardRequest);

    ResponseMessage deleteCard(String username, DeleteCardRequest deleteCardRequest);

    BusCardDTO abonmanOluştur(CreateSubscriptionRequest createSubscriptionRequest, String username) throws BusCardNotFoundException, AdminNotFoundException;

    List<BusCardDTO> getAllCards(String username);

    boolean qrStatus(String token);

    ResponseEntity<String> complete3DPayment(String paymentId, String conversationId, HttpServletRequest httpServletRequest);

    ResponseMessage topUp(String username, String cardNumber, @Valid TopUpBalanceRequest topUpBalanceRequest) throws BusCardNotFoundException, BusCardNotActiveException, BusCardIsBlockedException, MinumumTopUpAmountException, UserNotFoundException;

    // Login olmadan kart numarasıyla 3D top-up başlatma
    ResponseMessage topUpAsGuest(String cardNumber, @Valid TopUpBalanceRequest topUpBalanceRequest) throws BusCardNotFoundException, BusCardNotActiveException, BusCardIsBlockedException, MinumumTopUpAmountException;

    BusCardDTO balanceInquiry(String cardNumber) throws BusCardNotFoundException;

    ResponseMessage topUpUsingWallet(String username, @Valid TopUpCardRequest topUpCardRequest, HttpServletRequest httpServletRequest) throws BusCardIsBlockedException, BusCardNotActiveException, MinumumTopUpAmountException, InsufficientBalanceException, UserNotFoundException, BusCardNotFoundException, WalletNotFoundException;
}
