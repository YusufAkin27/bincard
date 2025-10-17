package akin.city_card.buscard.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.buscard.core.request.*;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.exceptions.CardPricingNotFoundException;
import akin.city_card.buscard.exceptions.ExpiredQrCodeException;
import akin.city_card.buscard.exceptions.InvalidQrCodeException;
import akin.city_card.buscard.service.abstracts.BusCardService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

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
    public BusCardDTO registerCard(@RequestBody RegisterCardRequest req, @AuthenticationPrincipal UserDetails userDetails) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.registerCard(req, userDetails.getUsername());
    }

    @PostMapping("/read")
    public BusCardDTO readCard(@AuthenticationPrincipal UserDetails userDetails, @RequestBody ReadCardRequest req) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.readCard(req.getUid(), userDetails.getUsername());
    }


    //bakiye yükleme
    @PostMapping("/top-up")
    public BusCardDTO topUpBalance(@AuthenticationPrincipal UserDetails userDetails, @RequestBody TopUpBalanceCardRequest request) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.topUpBalance(userDetails.getUsername(), request.getUid(), request.getAmount());

    }

    @PostMapping("/card-visa")
    public BusCardDTO cardVisa(@AuthenticationPrincipal UserDetails userDetails, @RequestBody ReadCardRequest request) throws UnauthorizedAccessException {
        isAdminOrSuperAdmin(userDetails);
        return busCardService.cardVisa(request, userDetails.getUsername());
    }

    @PostMapping("/card-blocked")
    public BusCardDTO cardBlocked(@RequestBody Map<String, Object> request) {
        return busCardService.cardBlocked(request);
    }

    @DeleteMapping("/card-blocked")
    public BusCardDTO deleteCardBlocked(@RequestBody Map<String, String> request) {
        return busCardService.deleteCardBlocked(request);
    }

    @PostMapping("/get-on")
    public BusCardDTO getOn(@RequestBody ReadCardRequest request) {
        return busCardService.getOn(request.getUid());
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
