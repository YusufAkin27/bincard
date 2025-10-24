package akin.city_card.wallet.controller;

import akin.city_card.bus.exceptions.UnauthorizedAccessException;
import akin.city_card.news.core.response.PageDTO;
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
import akin.city_card.user.repository.UserRepository;
import akin.city_card.wallet.core.request.*;
import akin.city_card.wallet.core.response.*;
import akin.city_card.wallet.exceptions.*;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletActivityType;
import akin.city_card.wallet.model.WalletStatus;
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
import org.springframework.security.access.prepost.PreAuthorize;
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
    private final UserRepository userRepository;

    // ========== Mevcut Endpoint'ler ==========
    //user
    @PostMapping(path = "/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseMessage create(
            @ModelAttribute CreateWalletRequest request,
            @AuthenticationPrincipal UserDetails user) throws UserNotFoundException, OnlyPhotosAndVideosException, PhotoSizeLargerException, IOException, VideoSizeLargerException, FileFormatCouldNotException {
        return walletService.createWallet(user.getUsername(), request);
    }

    //admin
    @PostMapping("/process")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage processIdentityRequest(
            @RequestBody @Valid ProcessIdentityRequest request,
            @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, IdentityVerificationRequestNotFoundException, UnauthorizedAreaException, AlreadyWalletUserException {
        return walletService.approveOrReject(request, userDetails.getUsername());
    }

    //admin
    @GetMapping("/identity-requests")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
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


    //user
    @PostMapping("/transfer")
    public ResponseMessage transfer(
            @AuthenticationPrincipal UserDetails sender,
            @RequestBody @Valid WalletTransferRequest walletTransferRequest) throws UserNotFoundException, ReceiverWalletNotFoundException, ReceiverNotFoundException, WalletNotFoundException, InsufficientFundsException, ReceiverWalletNotActiveException, WalletNotActiveException, NameAndSurnameAreWrongException {
        return walletService.transfer(sender.getUsername(), walletTransferRequest);
    }

    @GetMapping("/name")
    public ResponseEntity<String> getWibanToName(@RequestParam("input") String input) {
        String maskedName = walletService.getWibanToName(input);
        return ResponseEntity.ok(maskedName);
    }

    //user
    @PutMapping("/toggleWalletStatus")
    public ResponseMessage toggleWalletStatus(@AuthenticationPrincipal UserDetails user,
                                              @RequestParam(name = "isActive") boolean isActive) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException, WalletDeactivationException {
        return walletService.toggleWalletStatus(user.getUsername(), isActive);
    }

    //user
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

    //user
    @GetMapping("/transfer/{id}")
    public DataResponseMessage<?> getTransferDetail(
            @AuthenticationPrincipal UserDetails user,
            @PathVariable Long id) throws UserNotFoundException, TransferNotFoundException, UnauthorizedAccessException {
        return walletService.getTransferDetail(user.getUsername(), id);
    }

    //user
    @GetMapping("/my-wallet")
    public WalletDTO getMyWallet(@AuthenticationPrincipal UserDetails user) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {
        return walletService.getMyWallet(user.getUsername());
    }

    //user
    @GetMapping("/transfers/outgoing")
    public DataResponseMessage<Page<WalletTransactionDTO>> getOutgoingTransfers(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam int page,
            @RequestParam int size) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {

        Wallet wallet = walletService.getWalletByUsername(user.getUsername());
        Page<WalletTransactionDTO> transfers = walletService.getOutgoingTransfers(wallet.getId(), page, size);

        return DataResponseMessage.of(transfers);
    }

    //user
    @GetMapping("/transfers/incoming")
    public DataResponseMessage<Page<WalletTransactionDTO>> getIncomingTransfers(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam int page,
            @RequestParam int size) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {

        Wallet wallet = walletService.getWalletByUsername(user.getUsername());
        Page<WalletTransactionDTO> transfers = walletService.getIncomingTransfers(wallet.getId(), page, size);

        return DataResponseMessage.of(transfers);
    }

    //user
    @GetMapping("/balance/history")
    public DataResponseMessage<List<BalanceHistoryDTO>> getBalanceHistory(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {
        return walletService.getBalanceHistory(user.getUsername(), start, end);
    }

    //admin
    @PostMapping("/admin/change-status")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage changeWalletStatusAsAdmin(
            @RequestParam String userNumber,
            @RequestParam String statusReason,
            @RequestParam WalletStatus walletStatus,
            @AuthenticationPrincipal UserDetails admin) throws UserNotFoundException, WalletNotFoundException, AdminOrSuperAdminNotFoundException {
        return walletService.changeStatusAsAdmin(admin.getUsername(), userNumber, walletStatus, statusReason);
    }

    //user
    @PostMapping("/top-up")
    public ResponseMessage topUpBalance(
            @AuthenticationPrincipal UserDetails user,
            @Valid @RequestBody TopUpBalanceRequest topUpBalanceRequest) throws UserNotFoundException, WalletNotFoundException {
        return walletService.topUp(user.getUsername(), topUpBalanceRequest);
    }

    @PostMapping("/payment/3d-callback")
    public ResponseEntity<String> complete3DPayment(
            @RequestParam(name = "paymentId", required = false) String paymentId,
            @RequestParam(name = "conversationId", required = false) String conversationId) {

        return walletService.complete3DPayment(paymentId, conversationId);
    }


    // ========== QR Kod İşlemleri ==========
//user
    @PostMapping("/qr/generate")
    public DataResponseMessage<QRCodeDTO> generateQRCode(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam BigDecimal amount,
            @RequestParam(required = false) String description,
            @RequestParam(defaultValue = "300") int expirationMinutes) {
        return qrCodeService.generateQRCode(user.getUsername(), amount, description, expirationMinutes);
    }

    //user
    @PostMapping("/qr/generate/payment")
    public DataResponseMessage<QRCodeDTO> generatePaymentQRCode(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) String description) {
        return qrCodeService.generatePaymentQRCode(user.getUsername(), description);
    }

    //user
    @PostMapping("/qr/scan")
    public DataResponseMessage<?> scanQRCode(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam String qrData) {
        return qrCodeService.scanQRCode(user.getUsername(), qrData);
    }

    //user
    @PostMapping("/qr/scan/image")
    public DataResponseMessage<?> scanQRCodeFromImage(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam("image") MultipartFile image) {
        return qrCodeService.scanQRCodeFromImage(user.getUsername(), image);
    }

    //user
    @PostMapping("/qr/transfer")
    public ResponseMessage transferViaQR(
            @AuthenticationPrincipal UserDetails user,
            @RequestBody QRTransferRequest request) {
        return qrCodeService.transferViaQR(user.getUsername(), request);
    }

    //user
    @PostMapping("/qr/payment")
    public ResponseMessage payViaQR(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam String qrCode,
            @RequestParam BigDecimal amount,
            @RequestParam(required = false) String description) {
        return qrCodeService.payViaQR(user.getUsername(), qrCode, amount, description);
    }

    //user
    @GetMapping("/qr/history")
    public DataResponseMessage<List<QRCodeDTO>> getQRHistory(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return qrCodeService.getQRHistory(user.getUsername(), page, size);
    }

    //user
    @PostMapping("/qr/{qrId}/cancel")
    public ResponseMessage cancelQRCode(
            @AuthenticationPrincipal UserDetails user,
            @PathVariable Long qrId) {
        return qrCodeService.cancelQRCode(user.getUsername(), qrId);
    }


    // ========== İstatistik ve Raporlama ==========
//user
    @GetMapping("/stats")
    public DataResponseMessage<WalletStatsDTO> getWalletStats(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) throws UserNotFoundException, WalletNotFoundException {
        return walletService.getWalletStats(user.getUsername(), start, end);
    }

    //user
    @GetMapping("/report/monthly")
    public DataResponseMessage<byte[]> getMonthlyReport(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam int year,
            @RequestParam int month) throws UserNotFoundException, WalletNotFoundException {
        return walletService.getMonthlyReport(user.getUsername(), year, month);
    }

    //user
    @GetMapping("/report/yearly")
    public DataResponseMessage<byte[]> getYearlyReport(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam int year) throws UserNotFoundException, WalletNotFoundException {
        return walletService.getYearlyReport(user.getUsername(), year);
    }


    // ========== Admin İşlemleri ==========
//admin
    @GetMapping("/admin/all")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
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

    //admin
    @GetMapping("/admin/stats")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<Map<String, Object>> getSystemStats(
            @AuthenticationPrincipal UserDetails admin) throws AdminOrSuperAdminNotFoundException {
        return walletService.getSystemStats(admin.getUsername());
    }

    //admin
    @PostMapping("/admin/force-transaction")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
    public ResponseMessage forceTransaction(
            @AuthenticationPrincipal UserDetails admin,
            @RequestParam String userPhone,
            @RequestParam BigDecimal amount,
            @RequestParam String reason) throws UserNotFoundException, WalletNotFoundException, WalletNotActiveException {
        return walletService.forceTransaction(admin.getUsername(), userPhone, amount, reason);
    }

    //admin
    @GetMapping("/admin/suspicious-activities")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<PageDTO<TransferDetailsDTO>> getSuspiciousActivities(
            @AuthenticationPrincipal UserDetails admin,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) throws UserNotFoundException, AdminOrSuperAdminNotFoundException {
        return walletService.getSuspiciousActivities(admin.getUsername(), page, size);
    }


    // ========== Özel İşlemler ==========

    //admin
    @GetMapping("/admin/export/transactions/excel")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
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

    //admin
    @PostMapping("/export/pdf")
    @PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('WALLET_ADMIN') or hasAuthority('SUPERADMIN')")
    public DataResponseMessage<byte[]> exportTransactionsPDF(
            @AuthenticationPrincipal UserDetails user,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
        return walletService.exportTransactionsPDF(user.getUsername(), start, end);
    }
}