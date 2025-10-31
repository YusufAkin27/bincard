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
import akin.city_card.wallet.core.request.TopUpBalanceRequest;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
                .anyMatch(role -> role.equals("ADMIN_ALL") || role.equals("SUPERADMIN") || role.equals("BUS_CARD_ADMIN"));

        if (!authorized) {
            throw new UnauthorizedAccessException();
        }
    }

    @PostMapping("/register")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO registerCard(HttpServletRequest httpServletRequest, @RequestBody RegisterCardRequest req, @AuthenticationPrincipal UserDetails userDetails) throws UnauthorizedAccessException, AlreadyBusCardNumberException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.registerCard(httpServletRequest, req, userDetails.getUsername());
    }

    @PostMapping("/read")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO readCard(@AuthenticationPrincipal UserDetails userDetails, @RequestBody ReadCardRequest req) throws UnauthorizedAccessException, BusCardNotFoundException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.readCard(req.getUid(), userDetails.getUsername());
    }

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseEntity<Page<BusCardDTO>> getAllCards(
            @AuthenticationPrincipal UserDetails userDetails,
            Pageable pageable
    ) throws BusCardNotActiveException, BusCardNotFoundException, AdminNotFoundException {
        Page<BusCardDTO> result = busCardService.getAllCards(userDetails.getUsername(), pageable);
        return ResponseEntity.ok(result);
    }


    //bakiye yükleme
    @PostMapping("/top-up")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO topUpBalance(@AuthenticationPrincipal UserDetails userDetails, @RequestBody TopUpBalanceCardRequest request) throws UnauthorizedAccessException, BusCardNotActiveException, BusCardNotFoundException, AdminNotFoundException, TransactionCounterException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.topUpBalance(userDetails.getUsername(), request);

    }

    @PostMapping("/card-visa")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO cardVisa(@AuthenticationPrincipal UserDetails userDetails, @RequestBody ReadCardRequest request) throws UnauthorizedAccessException, BusCardNotStudentException, BusCardNotActiveException, BusCardNotFoundException, AdminNotFoundException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.cardVisa(request, userDetails.getUsername());
    }

    @PostMapping("/card-blocked")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO cardBlocked(@RequestBody ReadCardRequest request, @AuthenticationPrincipal UserDetails userDetails) throws BusCardNotActiveException, BusCardNotFoundException, BusCardAlreadyIsBlockedException, AdminNotFoundException {
        return busCardService.cardBlocked(request, userDetails.getUsername());
    }

    @GetMapping("/card-blocked")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public List<BusCardDTO> getBlockedCards(@AuthenticationPrincipal UserDetails userDetails) throws BusCardNotActiveException, BusCardNotFoundException, AdminNotFoundException {
        return busCardService.getBlockedCards(userDetails.getUsername());
    }


    @DeleteMapping("/card-blocked")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO deleteCardBlocked(@RequestBody ReadCardRequest request, @AuthenticationPrincipal UserDetails userDetails) throws BusCardNotActiveException, BusCardNotFoundException, BusCardAlreadyIsBlockedException, AdminNotFoundException, BusCardNotBlockedException {
        return busCardService.deleteCardBlocked(request, userDetails.getUsername());
    }

    @PostMapping("/abonman")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO abonmanOluştur(@RequestBody CreateSubscriptionRequest createSubscriptionRequest, @AuthenticationPrincipal UserDetails userDetails) throws BusCardNotFoundException, AdminNotFoundException {
        return busCardService.abonmanOluştur(createSubscriptionRequest, userDetails.getUsername());
    }


    @PostMapping("/get-on")
    public BusCardDTO getOn(@RequestBody GetOnBusRequest request) throws InsufficientBalanceException, CorruptedDataException, CardInactiveException, CardPricingNotFoundException, SubscriptionNotFoundException, SubscriptionExpiredException, BusNotFoundException {
        return busCardService.getOn(request);
    }

    //CRUD create -update delete temel işlemler
    @PostMapping("/card-pricing")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage createCardPricing(@AuthenticationPrincipal UserDetails userDetails, @RequestBody CreateCardPricingRequest createCardPricingRequest) throws AdminNotFoundException {
        return busCardService.createCardPricing(createCardPricingRequest, userDetails.getUsername());

    }

    @PutMapping("/card-pricing")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage updateCardPricing(@AuthenticationPrincipal UserDetails userDetails, @RequestBody UpdateCardPricingRequest updateCardPricingRequest) throws AdminNotFoundException, CardPricingNotFoundException {
        return busCardService.updateCardPricing(userDetails.getUsername(), updateCardPricingRequest);
    }

    @GetMapping("/card-pricing")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public List<CardPricingDTO> getAllCardPricing() {
        return busCardService.getAllCardPricing();
    }


    @PutMapping("/edit-card")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public BusCardDTO editCard(@AuthenticationPrincipal UserDetails userDetails, @RequestBody UpdateBusCardRequest updateCardRequest) throws BusCardNotFoundException {
        return busCardService.editCard(userDetails.getUsername(), updateCardRequest);
    }

    @DeleteMapping("/delete-card")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('BUS_CARD_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage deleteCard(@AuthenticationPrincipal UserDetails userDetails, @RequestBody ReadCardRequest deleteCardRequest) throws BusCardNotFoundException, AdminNotFoundException {
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

    @GetMapping("/qr-status/{token}")
    public boolean checkQrStatus(@PathVariable String token) {
        return busCardService.qrStatus(token);

    }


    @PostMapping("/scan-qr")
    public ResponseMessage scanQrCode(@RequestBody QrScanRequest request) throws UserNotFoundException, InvalidQrCodeException, WalletNotFoundException, InsufficientBalanceException, ExpiredQrCodeException, WalletNotActiveException, CardPricingNotFoundException {
        return busCardService.verifyQrToken(request.getQrToken());
    }


    @PostMapping("/top-up/card")
    public ResponseMessage topUpBalance(
            @Valid @RequestBody TopUpBalanceRequest topUpBalanceRequest,
            @RequestParam String cardNumber,
            @AuthenticationPrincipal UserDetails userDetails) throws BusCardIsBlockedException, UserNotFoundException, BusCardNotActiveException, BusCardNotFoundException, MinumumTopUpAmountException {
        if (userDetails != null){
            return busCardService.topUp(userDetails.getUsername(),cardNumber,topUpBalanceRequest);
        }
        // Giriş yapılmamışsa misafir olarak karta yükleme başlatt
        return busCardService.topUpAsGuest(cardNumber, topUpBalanceRequest);

    }

    @PostMapping("/payment/3d-callback")
    public ResponseEntity<String> complete3DPayment(
            @RequestParam(name = "paymentId", required = false) String paymentId,
            @RequestParam(name = "conversationId", required = false) String conversationId,
            HttpServletRequest httpServletRequest) {

        return busCardService.complete3DPayment(paymentId, conversationId,httpServletRequest);
    }
    @PostMapping("/top-up/wallet")
    public ResponseMessage topUpWallet(@Valid @RequestBody TopUpCardRequest topUpCardRequest,
                                       @AuthenticationPrincipal UserDetails userDetails,
                                       HttpServletRequest httpServletRequest) throws WalletNotFoundException, InsufficientBalanceException, WalletNotActiveException, BusCardIsBlockedException, UserNotFoundException, BusCardNotActiveException, BusCardNotFoundException, MinumumTopUpAmountException {
        return busCardService.topUpUsingWallet(userDetails.getUsername(),topUpCardRequest,httpServletRequest);
    }

    @GetMapping("/balance inquiry")
    public BusCardDTO balanceInquiry(@RequestParam String cardNumber) throws BusCardNotFoundException, WalletNotFoundException, WalletNotActiveException {
        return busCardService.balanceInquiry(cardNumber);
    }



}
