package akin.city_card.paymentPoint.controller;

import akin.city_card.news.core.response.PageDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.paymentPoint.core.request.AddPaymentPointRequest;
import akin.city_card.paymentPoint.core.request.UpdatePaymentPointRequest;
import akin.city_card.paymentPoint.core.response.PaymentPointDTO;
import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.paymentPoint.service.abstracts.PaymentPointService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/v1/api/payment-point")
@RequiredArgsConstructor
public class PaymentPointController {

    private final PaymentPointService paymentPointService;

    /**
     * Rol kontrolü yardımcı metodu
     */
    private boolean isAdminOrSuperAdmin(UserDetails userDetails) {
        if (userDetails == null) return false;
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ADMIN") || role.equals("SUPERADMIN"));
    }

    /**
     * Yeni ödeme noktası ekler - Sadece admin veya süper admin
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseMessage addPaymentPoint(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody AddPaymentPointRequest request) throws UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }
        return paymentPointService.add(request, userDetails.getUsername());
    }

    /**
     * Ödeme noktasını günceller - Sadece admin veya süper admin
     */
    @PutMapping("/{id}")
    public ResponseMessage updatePaymentPoint(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdatePaymentPointRequest request) throws UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }
        return paymentPointService.update(id, request, userDetails.getUsername());
    }

    /**
     * Belirli bir ödeme noktasını getirir - Herkes erişebilir
     */
    @GetMapping("/{id}")
    public DataResponseMessage<PaymentPointDTO> getPaymentPoint(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails != null ? userDetails.getUsername() : null;
        return paymentPointService.getById(id, username);
    }

    /**
     * Tüm ödeme noktalarını sayfalama ile getirir - Herkes erişebilir
     */
    @GetMapping
    public DataResponseMessage<PageDTO<PaymentPointDTO>> getAllPaymentPoints(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "name") String sort) throws UnauthorizedAreaException {
        String username = userDetails != null ? userDetails.getUsername() : null;
        Pageable pageable = PageRequest.of(page, size, Sort.by(sort));
        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }
        return paymentPointService.getAll(username, pageable);
    }

    /**
     * Konum bazlı arama ve filtreleme - Herkes erişebilir
     */
    @PostMapping("/search")
    public DataResponseMessage<PageDTO<PaymentPointDTO>> searchPaymentPoints(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam String query,
            @RequestParam double latitude,
            @RequestParam double longitude,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) throws UserNotFoundException {

        String username = userDetails != null ? userDetails.getUsername() : null;
        Pageable pageable = PageRequest.of(page, size);
        return paymentPointService.search(query, username, latitude, longitude, pageable);
    }


    /**
     * Yakındaki ödeme noktalarını getirir - Herkes erişebilir
     */
    @GetMapping("/nearby")
    public DataResponseMessage<PageDTO<PaymentPointDTO>> getNearbyPaymentPoints(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam double latitude,
            @RequestParam double longitude,
            @RequestParam(defaultValue = "5.0") double radiusKm,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        String username = userDetails != null ? userDetails.getUsername() : null;
        Pageable pageable = PageRequest.of(page, size);
        return paymentPointService.getNearby(latitude, longitude, radiusKm, username, pageable);
    }

    /**
     * Ödeme noktasını aktif/pasif yapar - Sadece admin veya süper admin
     */
    @PatchMapping("/{id}/status")
    public ResponseMessage togglePaymentPointStatus(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam boolean active) throws UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }
        return paymentPointService.toggleStatus(id, active, userDetails.getUsername());
    }

    /**
     * Ödeme noktasını siler - Sadece admin veya süper admin
     */
    @DeleteMapping("/{id}")
    public ResponseMessage deletePaymentPoint(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) throws UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }
        return paymentPointService.delete(id, userDetails.getUsername());
    }

    /**
     * Ödeme noktasına fotoğraf ekler - Sadece admin veya süper admin
     */
    @PostMapping("/{id}/photos")
    public ResponseMessage addPaymentPointPhotos(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("files") List<MultipartFile> files) throws UnauthorizedAreaException {

        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }

        if (files == null || files.isEmpty()) {
            return ResponseMessage.builder()
                    .isSuccess(false)
                    .message("Yüklenecek fotoğraf bulunamadı.")
                    .build();
        }

        return paymentPointService.addPhotos(id, files, userDetails.getUsername());
    }

    /**
     * Ödeme noktasından fotoğraf siler - Sadece admin veya süper admin
     */
    @DeleteMapping("/{id}/photos/{photoId}")
    public ResponseMessage deletePaymentPointPhoto(
            @PathVariable Long id,
            @PathVariable Long photoId,
            @AuthenticationPrincipal UserDetails userDetails) throws UnauthorizedAreaException {
        if (!isAdminOrSuperAdmin(userDetails)) {
            throw new UnauthorizedAreaException();
        }
        return paymentPointService.deletePhoto(id, photoId, userDetails.getUsername());
    }

    /**
     * Şehir bazlı ödeme noktalarını getirir - Herkes erişebilir
     */
    @GetMapping("/by-city/{city}")
    public ResponseEntity<DataResponseMessage<PageDTO<PaymentPointDTO>>> getPaymentPointsByCity(
            @PathVariable String city,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        String username = userDetails != null ? userDetails.getUsername() : null;
        Pageable pageable = PageRequest.of(page, size);
        DataResponseMessage<PageDTO<PaymentPointDTO>> result = paymentPointService.getByCity(city, username, pageable);
        return ResponseEntity.ok(result);
    }

    /**
     * Ödeme yöntemi bazlı filtreleme - Herkes erişebilir
     */
    @GetMapping("/by-payment-method")
    public ResponseEntity<DataResponseMessage<PageDTO<PaymentPointDTO>>> getPaymentPointsByPaymentMethod(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam PaymentMethod paymentMethod,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        String username = userDetails != null ? userDetails.getUsername() : null;
        Pageable pageable = PageRequest.of(page, size);
        DataResponseMessage<PageDTO<PaymentPointDTO>> result = paymentPointService.getByPaymentMethod(paymentMethod, username, pageable);
        return ResponseEntity.ok(result);
    }
}