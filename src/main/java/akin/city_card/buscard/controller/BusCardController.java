package akin.city_card.buscard.controller;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.InsufficientBalanceException;
import akin.city_card.buscard.core.request.CreateCardPricingRequest;
import akin.city_card.buscard.core.request.QrScanRequest;
import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.buscard.core.request.UpdateCardPricingRequest;
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
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/buscard")
@RequiredArgsConstructor
public class BusCardController {
    private final BusCardService busCardService;

    @PostMapping("/register")
    public ResponseEntity<?> registerCard(@RequestBody RegisterCardRequest req) {
        return busCardService.registerCard(req);
    }

    @PostMapping("/read")
    public ResponseEntity<?> readCard(@RequestBody Map<String, String> request) {
        try {
            String uid = request.get("uid");
            if (uid == null || uid.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "UID zorunlu"));
            }

            return busCardService.readCard(uid);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }


    //bakiye yükleme
    @PostMapping("/top-up")
    public ResponseEntity<?> topUpBalance(@RequestBody Map<String, Object> request) {

        String uid = (String) request.get("uid");
        Number amount = (Number) request.get("amount");
        return busCardService.topUpBalance(uid, BigDecimal.valueOf(amount.doubleValue()));

    }

    @PostMapping("/card-visa")
    public ResponseEntity<?> cardVisa(@RequestBody Map<String, Object> request) {
        return busCardService.cardVisa(request);
    }

    @PostMapping("/card-blocked")
    public ResponseEntity<?> cardBlocked(@RequestBody Map<String, Object> request) {
        return busCardService.cardBlocked(request);
    }

    @DeleteMapping("/card-blocked")
    public ResponseEntity<?> deleteCardBlocked(@RequestBody Map<String, String> request) {
        return busCardService.deleteCardBlocked(request);
    }

    @PostMapping("/get-on")
    public ResponseEntity<?> getOn(@RequestBody Map<String, String> request) {
        try {
            String uid = request.get("uid");

            if (uid == null || uid.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "UID zorunlu"));
            }

            return busCardService.getOn(uid);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
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
