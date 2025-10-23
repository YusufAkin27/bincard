package akin.city_card.buscard.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.buscard.core.request.*;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.*;
import akin.city_card.buscard.service.abstracts.BusCardService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import com.iyzipay.request.DeleteCardRequest;
import io.craftgate.request.UpdateCardRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/buscard")
@RequiredArgsConstructor
public class BusCardController {
    private final BusCardService busCardService;

    private void isAdminOrSuperAdmin(UserDetails userDetails) throws UnauthorizedAccessException {
        if (userDetails == null || userDetails.getAuthorities() == null) {
            throw new UnauthorizedAccessException();
        }

        boolean authorized = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ADMIN") || role.equals("SUPERADMIN"));

        if (!authorized) {
            throw new UnauthorizedAccessException();
        }
    }

    @PostMapping("/register")
    public BusCardDTO registerCard(HttpServletRequest httpServletRequest, @RequestBody RegisterCardRequest req, @AuthenticationPrincipal UserDetails userDetails) throws UnauthorizedAccessException, AlreadyBusCardNumberException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.registerCard(httpServletRequest, req, userDetails.getUsername());
    }

    @PostMapping("/read")
    public BusCardDTO readCard(@AuthenticationPrincipal UserDetails userDetails, @RequestBody ReadCardRequest req) throws UnauthorizedAccessException, BusCardNotFoundException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.readCard(req.getUid(), userDetails.getUsername());
    }


    //bakiye yükleme
    @PostMapping("/top-up")
    public BusCardDTO topUpBalance(@AuthenticationPrincipal UserDetails userDetails, @RequestBody TopUpBalanceCardRequest request) throws UnauthorizedAccessException, BusCardNotActiveException, BusCardNotFoundException, AdminNotFoundException, TransactionCounterException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.topUpBalance(userDetails.getUsername(), request);

    }

    @PostMapping("/card-visa")
    public BusCardDTO cardVisa(@AuthenticationPrincipal UserDetails userDetails, @RequestBody ReadCardRequest request) throws UnauthorizedAccessException, BusCardNotStudentException, BusCardNotActiveException, BusCardNotFoundException, AdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.cardVisa(request, userDetails.getUsername());
    }

    @PostMapping("/card-blocked")
    public BusCardDTO cardBlocked(@RequestBody ReadCardRequest request, @AuthenticationPrincipal UserDetails userDetails) throws BusCardNotActiveException, BusCardNotFoundException, BusCardAlreadyIsBlockedException, AdminNotFoundException {
        return busCardService.cardBlocked(request, userDetails.getUsername());
    }

    @GetMapping("/card-blocked")
    public List<BusCardDTO> getBlockedCards(@AuthenticationPrincipal UserDetails userDetails) throws BusCardNotActiveException, BusCardNotFoundException, AdminNotFoundException {
        return busCardService.getBlockedCards(userDetails.getUsername());
    }

    @DeleteMapping("/card-blocked")
    public BusCardDTO deleteCardBlocked(@RequestBody ReadCardRequest request, @AuthenticationPrincipal UserDetails userDetails) throws BusCardNotActiveException, BusCardNotFoundException, BusCardAlreadyIsBlockedException, AdminNotFoundException, BusCardNotBlockedException {
        return busCardService.deleteCardBlocked(request, userDetails.getUsername());
    }

    @PostMapping("/abonman")
    public BusCardDTO abonmanOluştur(@RequestBody CreateSubscriptionRequest createSubscriptionRequest, @AuthenticationPrincipal UserDetails userDetails) {
        return busCardService.abonmanOluştur(createSubscriptionRequest, userDetails.getUsername());
    }


    @PostMapping("/get-on")
    public BusCardDTO getOn(@RequestBody GetOnBusRequest request) throws BusCardNotFoundException, InsufficientBalanceException, CorruptedDataException, CardInactiveException, CardPricingNotFoundException, SubscriptionNotFoundException, SubscriptionExpiredException {
        return busCardService.getOn(request);
    }

    //CRUD create -update delete temel işlemler
    @PostMapping("/card-pricing")
    public ResponseMessage createCardPricing(@AuthenticationPrincipal UserDetails userDetails, @RequestBody CreateCardPricingRequest createCardPricingRequest) throws AdminNotFoundException {
        return busCardService.createCardPricing(createCardPricingRequest, userDetails.getUsername());

    }

    @PutMapping("/card-pricing")
    public ResponseMessage updateCardPricing(@AuthenticationPrincipal UserDetails userDetails, @RequestBody UpdateCardPricingRequest updateCardPricingRequest) throws AdminNotFoundException, CardPricingNotFoundException {
        return busCardService.updateCardPricing(userDetails.getUsername(), updateCardPricingRequest);
    }

    @GetMapping("/card-pricing")
    public List<CardPricingDTO> getAllCardPricing() {
        return busCardService.getAllCardPricing();
    }


    @PutMapping("/edit-card")
    public BusCardDTO editCard(@AuthenticationPrincipal UserDetails userDetails, @RequestBody UpdateCardRequest updateCardRequest) {
        return busCardService.editCard(userDetails.getUsername(), updateCardRequest);
    }

    @DeleteMapping("/delete-card")
    public ResponseMessage deleteCard(@AuthenticationPrincipal UserDetails userDetails, @RequestBody DeleteCardRequest deleteCardRequest) {
        return busCardService.deleteCard(userDetails.getUsername(), deleteCardRequest);
    }

    @PostMapping("/generate-qr")
    public ResponseEntity<byte[]> generateQrCode(@AuthenticationPrincipal UserDetails userDetails)
            throws Exception {
        String username = userDetails.getUsername();
        byte[] qrBytes = busCardService.generateQrCode(username);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "image/png")
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"qrcode.png\"")
                .body(qrBytes);
    }

    @PostMapping("/scan-qr")
    public ResponseEntity<ResponseMessage> scanQrCode(@RequestBody QrScanRequest request) throws UserNotFoundException, InvalidQrCodeException, WalletNotFoundException, InsufficientBalanceException, ExpiredQrCodeException {
        ResponseMessage response = busCardService.verifyQrToken(request.getQrToken());
        return ResponseEntity.ok(response);
    }

}
