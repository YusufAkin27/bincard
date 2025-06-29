package akin.city_card.wallet.controller;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.wallet.core.request.CreateWalletRequest;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.model.WalletActivityType;
import akin.city_card.wallet.service.abstracts.WalletService;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/v1/api/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletService walletService;

    @PostMapping("/create")
    public DataResponseMessage<WalletDTO> create(@RequestBody CreateWalletRequest createWalletRequest, @AuthenticationPrincipal UserDetails user) {
        return walletService.createWallet(user.getUsername(),createWalletRequest);
    }

    @GetMapping("/balance")
    public DataResponseMessage<BigDecimal> getBalance(@AuthenticationPrincipal UserDetails user) {
        return walletService.getWalletBalance(user.getUsername());
    }

    @PostMapping("/transfer")
    public ResponseMessage transfer(
            @AuthenticationPrincipal UserDetails sender,
            @RequestParam String receiverPhone,
            @RequestParam BigDecimal amount) {
        return walletService.transfer(sender.getUsername(), receiverPhone, amount);
    }

    @PostMapping("/deactivate")
    public ResponseMessage deactivate(@AuthenticationPrincipal UserDetails user) {
        return walletService.deactivateWallet(user.getUsername());
    }

    @PostMapping("/activate")
    public ResponseMessage activate(@AuthenticationPrincipal UserDetails user) {
        return walletService.activateWallet(user.getUsername());
    }

    @GetMapping("/activities")
    public DataResponseMessage<List<WalletActivityDTO>> getActivities(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) WalletActivityType type,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
        return walletService.getActivities(user.getUsername(), type, start, end);
    }

    @GetMapping("/activities/page")
    public DataResponseMessage<List<WalletActivityDTO>> getPagedActivities(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) WalletActivityType type) {
        return walletService.getActivitiesPaged(user.getUsername(), type, page, size);
    }
    // 2. Belirli bir transferin detayını getir
    @GetMapping("/transfer/{id}")
    public DataResponseMessage<?> getTransferDetail(
            @AuthenticationPrincipal UserDetails user,
            @PathVariable Long id) {
        return walletService.getTransferDetail(user.getUsername(), id);
    }
    // 3. Cüzdan bakiyesinin zaman içindeki değişimini getir (grafik desteği için)
    @GetMapping("/balance/history")
    public DataResponseMessage<List<BigDecimal>> getBalanceHistory(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
        return walletService.getBalanceHistory(user.getUsername(), start, end);
    }

    @PostMapping("/admin/change-status")
    public ResponseMessage changeWalletStatusAsAdmin(
            @RequestParam String userNumber,
            @RequestParam String statusReason,
            @RequestParam boolean activate,
            @AuthenticationPrincipal UserDetails admin) {
        return walletService.changeStatusAsAdmin(admin.getUsername(), userNumber, activate, statusReason);
    }

    @PostMapping("/top-up")
    public ResponseMessage topUpBalance(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam BigDecimal amount,
            @RequestParam String cardNumber,
            @RequestParam String cardExpiry,
            @RequestParam String cardCvc) {
        return walletService.topUp(user.getUsername(), amount, cardNumber, cardExpiry, cardCvc);
    }

}
