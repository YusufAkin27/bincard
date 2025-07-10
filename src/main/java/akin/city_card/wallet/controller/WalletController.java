package akin.city_card.wallet.controller;

import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.response.IdentityVerificationRequestDTO;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.user.model.RequestStatus;
import akin.city_card.wallet.core.request.*;
import akin.city_card.wallet.core.response.QRCodeDTO;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.core.response.WalletStatsDTO;
import akin.city_card.wallet.exceptions.*;
import akin.city_card.wallet.model.WalletActivityType;
import akin.city_card.wallet.service.abstracts.QRCodeService;
import akin.city_card.wallet.service.abstracts.WalletService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletService walletService;
    private final QRCodeService qrCodeService;

    // ========== Mevcut Endpoint'ler ==========
    @PostMapping(path = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage create(
            @ModelAttribute CreateWalletRequest request,
            @AuthenticationPrincipal UserDetails user) throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException {
        return walletService.createWallet(user.getUsername(), request);
    }

    @PostMapping("/process")
    public ResponseMessage processIdentityRequest(
            @RequestBody @Valid ProcessIdentityRequest request,
            @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, IdentityVerificationRequestNotFoundException, UnauthorizedAreaException, AlreadyWalletUserException {
        return walletService.approveOrReject(request, userDetails.getUsername());
    }

    @GetMapping("/identity-requests")
    public DataResponseMessage<Page<IdentityVerificationRequestDTO>> getIdentityRequests(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(required = false) RequestStatus status,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "requestedAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir
    ) throws UserNotFoundException, UnauthorizedAreaException {
        return walletService.getIdentityRequests(
                userDetails.getUsername(), status, startDate, endDate, page, size, sortBy, sortDir
        );
    }

    @GetMapping("/balance")
    public DataResponseMessage<BigDecimal> getBalance(@AuthenticationPrincipal UserDetails user) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {
        return walletService.getWalletBalance(user.getUsername());
    }

    @PostMapping("/transfer")
    public ResponseMessage transfer(
            @AuthenticationPrincipal UserDetails sender,
            @RequestBody @Valid WalletTransferRequest walletTransferRequest) throws UserNotFoundException, ReceiverWalletNotFoundException, ReceiverNotFoundException, WalletNotFoundException, InsufficientFundsException, ReceiverWalletNotActiveException, WalletNotActiveException {
        return walletService.transfer(sender.getUsername(), walletTransferRequest);
    }

    @PutMapping("/toggleWalletStatus")
    public ResponseMessage toggleWalletStatus(@AuthenticationPrincipal UserDetails user,
                                              @RequestParam(name = "isActive") boolean isActive) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException, WalletDeactivationException {
        return walletService.toggleWalletStatus(user.getUsername(),isActive);
    }


    @GetMapping("/activities")
    public DataResponseMessage<Page<WalletActivityDTO>> getActivities(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) WalletActivityType type,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "activityDate,desc") String sort
    ) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {

        Pageable pageable = PageRequest.of(page, size, parseSortParam(sort));

        return walletService.getActivities(
                user.getUsername(),
                type,
                start,
                end,
                pageable
        );
    }
    private Sort parseSortParam(String sortParam) {
        if (sortParam == null || sortParam.isBlank()) {
            return Sort.by(Sort.Order.desc("activityDate"));
        }

        String[] parts = sortParam.split(",");
        String property = parts[0];
        Sort.Direction direction = (parts.length == 2) ? Sort.Direction.fromString(parts[1]) : Sort.Direction.ASC;

        return Sort.by(new Sort.Order(direction, property));
    }




    @GetMapping("/transfer/{id}")
    public DataResponseMessage<?> getTransferDetail(
            @AuthenticationPrincipal UserDetails user,
            @PathVariable Long id) throws UserNotFoundException, TransferNotFoundException, UnauthorizedAccessException {
        return walletService.getTransferDetail(user.getUsername(), id);
    }


    @GetMapping("/my-wallet")
    public WalletDTO getMyWallet(@AuthenticationPrincipal UserDetails user) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {
        return walletService.getMyWallet(user.getUsername());
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
        return walletService.topUp(user.getUsername(), topUpBalanceRequest);
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
    public DataResponseMessage<Page<WalletDTO>> getAllWallets(
            @AuthenticationPrincipal UserDetails admin,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "id,desc") String sort) {

        Pageable pageable = PageRequest.of(page, size, parseSortParams(sort));

        return walletService.getAllWallets(admin.getUsername(), pageable);
    }
    private Sort parseSortParams(String sortParams) {
        List<Sort.Order> orders = new ArrayList<>();

        if (sortParams == null || sortParams.isBlank()) {
            return Sort.by(Sort.Order.desc("id")); // varsayılan sıralama
        }

        String[] sortPairs = sortParams.split(";"); // çoklu sıralama için id,desc;createdAt,asc gibi kullanım

        for (String pair : sortPairs) {
            String[] parts = pair.split(",");
            if (parts.length == 2) {
                orders.add(new Sort.Order(Sort.Direction.fromString(parts[1]), parts[0]));
            } else {
                orders.add(new Sort.Order(Sort.Direction.ASC, parts[0]));
            }
        }

        return Sort.by(orders);
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


    @GetMapping("/admin/export/transactions/excel")
    public ResponseEntity<byte[]> exportAllTransactionsExcel(
            @AuthenticationPrincipal UserDetails admin,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end
    ) throws Exception {
        DataResponseMessage<byte[]> response = walletService.exportTransactionsExcel(admin.getUsername(), start, end);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=transactions.xlsx")
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .body(response.getData());
    }


    @PostMapping("/export/pdf")
    public DataResponseMessage<byte[]> exportTransactionsPDF(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
        return walletService.exportTransactionsPDF(user.getUsername(), start, end);
    }
}