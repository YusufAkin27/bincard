package akin.city_card.wallet.controller;

import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.wallet.core.request.ApproveIdentityRequest;
import akin.city_card.wallet.core.request.TopUpBalanceRequest;
import akin.city_card.wallet.core.response.WalletStatsDTO;
import akin.city_card.wallet.core.request.CreateWalletRequest;

import akin.city_card.wallet.core.request.QRTransferRequest;
import akin.city_card.wallet.core.response.QRCodeDTO;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.exceptions.AlreadyWalletUserException;
import akin.city_card.wallet.exceptions.IdentityVerificationRequestNotFoundException;
import akin.city_card.wallet.exceptions.WalletNotActiveException;
import akin.city_card.wallet.exceptions.WalletNotFoundException;
import akin.city_card.wallet.model.WalletActivityType;
import akin.city_card.wallet.service.abstracts.QRCodeService;
import akin.city_card.wallet.service.abstracts.WalletService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletService walletService;
    private final QRCodeService qrCodeService;

    // ========== Mevcut Endpoint'ler ==========
    @PostMapping("/create")
    public ResponseMessage create(
            @ModelAttribute CreateWalletRequest request,
            @AuthenticationPrincipal UserDetails user) throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException {
        return walletService.createWallet(user.getUsername(), request);
    }

    @PostMapping("/approve")
    public ResponseMessage approveIdentityRequest(
            @RequestBody @Valid ApproveIdentityRequest request,
            @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, IdentityVerificationRequestNotFoundException, UnauthorizedAreaException, AlreadyWalletUserException {
        return walletService.approveOrReject(request, userDetails.getUsername());
    }

    @GetMapping("/balance")
    public DataResponseMessage<BigDecimal> getBalance(@AuthenticationPrincipal UserDetails user) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {
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

    @GetMapping("/transfer/{id}")
    public DataResponseMessage<?> getTransferDetail(
            @AuthenticationPrincipal UserDetails user,
            @PathVariable Long id) {
        return walletService.getTransferDetail(user.getUsername(), id);
    }

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
          @Valid @RequestBody TopUpBalanceRequest topUpBalanceRequest) throws UserNotFoundException, WalletNotFoundException {
        return walletService.topUp(user.getUsername(),topUpBalanceRequest);
    }

    // ========== QR Kod İşlemleri ==========

    @PostMapping("/qr/generate")
    public DataResponseMessage<QRCodeDTO> generateQRCode(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam BigDecimal amount,
            @RequestParam(required = false) String description,
            @RequestParam(defaultValue = "300") int expirationMinutes) {
        return qrCodeService.generateQRCode(user.getUsername(), amount, description, expirationMinutes);
    }

    @PostMapping("/qr/generate/payment")
    public DataResponseMessage<QRCodeDTO> generatePaymentQRCode(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) String description) {
        return qrCodeService.generatePaymentQRCode(user.getUsername(), description);
    }

    @PostMapping("/qr/scan")
    public DataResponseMessage<?> scanQRCode(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam String qrData) {
        return qrCodeService.scanQRCode(user.getUsername(), qrData);
    }

    @PostMapping("/qr/scan/image")
    public DataResponseMessage<?> scanQRCodeFromImage(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam("image") MultipartFile image) {
        return qrCodeService.scanQRCodeFromImage(user.getUsername(), image);
    }

    @PostMapping("/qr/transfer")
    public ResponseMessage transferViaQR(
            @AuthenticationPrincipal UserDetails user,
            @RequestBody QRTransferRequest request) {
        return qrCodeService.transferViaQR(user.getUsername(), request);
    }

    @PostMapping("/qr/payment")
    public ResponseMessage payViaQR(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam String qrCode,
            @RequestParam BigDecimal amount,
            @RequestParam(required = false) String description) {
        return qrCodeService.payViaQR(user.getUsername(), qrCode, amount, description);
    }

    @GetMapping("/qr/history")
    public DataResponseMessage<List<QRCodeDTO>> getQRHistory(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return qrCodeService.getQRHistory(user.getUsername(), page, size);
    }

    @PostMapping("/qr/{qrId}/cancel")
    public ResponseMessage cancelQRCode(
            @AuthenticationPrincipal UserDetails user,
            @PathVariable Long qrId) {
        return qrCodeService.cancelQRCode(user.getUsername(), qrId);
    }

    // ========== Transfer İşlemleri ==========

    @PostMapping("/transfer/wiban")
    public ResponseMessage transferToWiban(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam String receiverWiban,
            @RequestParam BigDecimal amount,
            @RequestParam(required = false) String description) {
        return walletService.transferToWiban(user.getUsername(), receiverWiban, amount, description);
    }

    @PostMapping("/transfer/email")
    public ResponseMessage transferToEmail(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam String receiverEmail,
            @RequestParam BigDecimal amount,
            @RequestParam(required = false) String description) {
        return walletService.transferToEmail(user.getUsername(), receiverEmail, amount, description);
    }



    // ========== Bakiye ve Para Yatırma İşlemleri ==========

    @PostMapping("/withdraw")
    public ResponseMessage withdrawToBank(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam BigDecimal amount,
            @RequestParam String bankAccount,
            @RequestParam String bankCode) {
        return walletService.withdrawToBank(user.getUsername(), amount, bankAccount, bankCode);
    }



    @GetMapping("/withdraw/history")
    public DataResponseMessage<List<?>> getWithdrawHistory(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return walletService.getWithdrawHistory(user.getUsername(), page, size);
    }



    // ========== İstatistik ve Raporlama ==========

    @GetMapping("/stats")
    public DataResponseMessage<WalletStatsDTO> getWalletStats(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
        return walletService.getWalletStats(user.getUsername(), start, end);
    }



    @GetMapping("/report/monthly")
    public DataResponseMessage<byte[]> getMonthlyReport(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam int year,
            @RequestParam int month) {
        return walletService.getMonthlyReport(user.getUsername(), year, month);
    }

    @GetMapping("/report/yearly")
    public DataResponseMessage<byte[]> getYearlyReport(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam int year) {
        return walletService.getYearlyReport(user.getUsername(), year);
    }

    // ========== Kullanıcı Yönetimi ve Profil ==========

    @GetMapping("/info")
    public DataResponseMessage<WalletDTO> getWalletInfo(
            @AuthenticationPrincipal UserDetails user) {
        return walletService.getWalletInfo(user.getUsername());
    }

    // ========== Bildirim ve Ayarlar ==========

    @PostMapping("/notifications/settings")
    public ResponseMessage setNotificationSettings(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam boolean emailNotifications,
            @RequestParam boolean smsNotifications,
            @RequestParam boolean pushNotifications) {
        return walletService.setNotificationSettings(user.getUsername(), emailNotifications, smsNotifications, pushNotifications);
    }

    @GetMapping("/notifications/settings")
    public DataResponseMessage<?> getNotificationSettings(
            @AuthenticationPrincipal UserDetails user) {
        return walletService.getNotificationSettings(user.getUsername());
    }




    // ========== Admin İşlemleri ==========

    @GetMapping("/admin/all")
    public DataResponseMessage<List<WalletDTO>> getAllWallets(
            @AuthenticationPrincipal UserDetails admin,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return walletService.getAllWallets(admin.getUsername(), page, size);
    }

    @GetMapping("/admin/stats")
    public DataResponseMessage<Map<String, Object>> getSystemStats(
            @AuthenticationPrincipal UserDetails admin) {
        return walletService.getSystemStats(admin.getUsername());
    }

    @PostMapping("/admin/force-transaction")
    public ResponseMessage forceTransaction(
            @AuthenticationPrincipal UserDetails admin,
            @RequestParam String userPhone,
            @RequestParam BigDecimal amount,
            @RequestParam String reason) {
        return walletService.forceTransaction(admin.getUsername(), userPhone, amount, reason);
    }


    @GetMapping("/admin/suspicious-activities")
    public DataResponseMessage<List<?>> getSuspiciousActivities(
            @AuthenticationPrincipal UserDetails admin,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return walletService.getSuspiciousActivities(admin.getUsername(), page, size);
    }



    // ========== Özel İşlemler ==========


    @PostMapping("/export/csv")
    public DataResponseMessage<byte[]> exportTransactionsCSV(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
        return walletService.exportTransactionsCSV(user.getUsername(), start, end);
    }

    @PostMapping("/export/pdf")
    public DataResponseMessage<byte[]> exportTransactionsPDF(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
        return walletService.exportTransactionsPDF(user.getUsername(), start, end);
    }
}