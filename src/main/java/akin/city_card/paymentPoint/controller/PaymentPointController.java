package akin.city_card.paymentPoint.controller;


import akin.city_card.paymentPoint.core.request.AddPaymentPointRequest;
import akin.city_card.paymentPoint.core.request.PaymentPointSearchRequest;
import akin.city_card.paymentPoint.core.request.UpdatePaymentPointRequest;
import akin.city_card.paymentPoint.core.response.PaymentPointDTO;
import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.paymentPoint.service.abstracts.PaymentPointService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/v1/api/payment-point")
@RequiredArgsConstructor
public class PaymentPointController {

    private final PaymentPointService paymentPointService;

    /**
     * Yeni ödeme noktası ekler
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseMessage addPaymentPoint(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody AddPaymentPointRequest request) {
        return paymentPointService.add(request, userDetails.getUsername());
    }

    /**
     * Ödeme noktasını günceller
     */
    @PutMapping("/{id}")
    public ResponseMessage updatePaymentPoint(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdatePaymentPointRequest request) {
        return paymentPointService.update(id, request, userDetails.getUsername());
    }

    /**
     * Belirli bir ödeme noktasını getirir
     */
    @GetMapping("/{id}")
    public DataResponseMessage<PaymentPointDTO> getPaymentPoint(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {
        return paymentPointService.getById(id, userDetails.getUsername());
    }

    /**
     * Tüm ödeme noktalarını sayfalama ile getirir
     */
    @GetMapping
    public DataResponseMessage<Page<PaymentPointDTO>> getAllPaymentPoints(
            @AuthenticationPrincipal UserDetails userDetails,
            Pageable pageable) {
        return paymentPointService.getAll(userDetails.getUsername(), pageable);
    }

    /**
     * Konum bazlı arama ve filtreleme (tek request'te tüm filtreleme seçenekleri)
     */
    @PostMapping("/search")
    public DataResponseMessage<Page<PaymentPointDTO>> searchPaymentPoints(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody PaymentPointSearchRequest searchRequest,
            Pageable pageable) {
        return paymentPointService.search(searchRequest, userDetails.getUsername(), pageable);
    }

    /**
     * Yakındaki ödeme noktalarını getirir
     */
    @GetMapping("/nearby")
    public DataResponseMessage<Page<PaymentPointDTO>> getNearbyPaymentPoints(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam double latitude,
            @RequestParam double longitude,
            @RequestParam(defaultValue = "5.0") double radiusKm,
            Pageable pageable) {
        return paymentPointService.getNearby(latitude, longitude, radiusKm, userDetails.getUsername(), pageable);
    }

    /**
     * Ödeme noktasını aktif/pasif yapar
     */
    @PatchMapping("/{id}/status")
    public ResponseMessage togglePaymentPointStatus(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam boolean active) {
        return paymentPointService.toggleStatus(id, active, userDetails.getUsername());
    }

    /**
     * Ödeme noktasını siler
     */
    @DeleteMapping("/{id}")
    public ResponseMessage deletePaymentPoint(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {
        return paymentPointService.delete(id, userDetails.getUsername());
    }

    /**
     * Ödeme noktasına fotoğraf ekler
     */
    @PostMapping("/{id}/photos")
    public ResponseMessage addPaymentPointPhotos(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("files") List<MultipartFile> files) {
        return paymentPointService.addPhotos(id, files, userDetails.getUsername());
    }

    /**
     * Ödeme noktasından fotoğraf siler
     */
    @DeleteMapping("/{id}/photos/{photoId}")
    public ResponseMessage deletePaymentPointPhoto(
            @PathVariable Long id,
            @PathVariable Long photoId,
            @AuthenticationPrincipal UserDetails userDetails) {
        return paymentPointService.deletePhoto(id, photoId, userDetails.getUsername());
    }

    /**
     * Şehir bazlı ödeme noktalarını getirir
     */
    @GetMapping("/by-city/{city}")
    public DataResponseMessage<Page<PaymentPointDTO>> getPaymentPointsByCity(
            @PathVariable String city,
            @AuthenticationPrincipal UserDetails userDetails,
            Pageable pageable) {
        return paymentPointService.getByCity(city, userDetails.getUsername(), pageable);
    }

    /**
     * Ödeme yöntemi bazlı filtreleme
     */
    @GetMapping("/by-payment-method")
    public DataResponseMessage<Page<PaymentPointDTO>> getPaymentPointsByPaymentMethod(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam PaymentMethod paymentMethod,
            Pageable pageable) {
        return paymentPointService.getByPaymentMethod(paymentMethod, userDetails.getUsername(), pageable);
    }
}