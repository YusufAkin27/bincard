package akin.city_card.paymentPoint.service.concretes;

import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.paymentPoint.core.converter.PaymentPointConverter;
import akin.city_card.paymentPoint.core.request.AddPaymentPointRequest;
import akin.city_card.paymentPoint.core.request.PaymentPointSearchRequest;
import akin.city_card.paymentPoint.core.request.UpdatePaymentPointRequest;
import akin.city_card.paymentPoint.core.response.PaymentPointDTO;
import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.paymentPoint.model.PaymentPhoto;
import akin.city_card.paymentPoint.model.PaymentPoint;
import akin.city_card.paymentPoint.repository.PaymentPointRepository;
import akin.city_card.paymentPoint.service.abstracts.PaymentPointService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PaymentPointManager implements PaymentPointService {

    private final PaymentPointRepository paymentPointRepository;
    private final PaymentPointConverter paymentPointConverter;
    private final MediaUploadService fileUploadService;

    @Override
    public ResponseMessage add(AddPaymentPointRequest request, String username) {
        try {
            PaymentPoint paymentPoint = paymentPointConverter.toEntity(request);
            paymentPointRepository.save(paymentPoint);

            log.info("Payment point added successfully by user: {}", username);
            return ResponseMessage.builder()
                    .isSuccess(true)
                    .message("Ödeme noktası başarıyla eklendi")
                    .build();
        } catch (Exception e) {
            log.error("Error adding payment point by user: {}", username, e);
            return ResponseMessage.builder()
                    .isSuccess(false)
                    .message("Ödeme noktası eklenirken hata oluştu: " + e.getMessage())
                    .build();
        }
    }

    @Override
    public ResponseMessage update(Long id, UpdatePaymentPointRequest request, String username) {
        try {
            PaymentPoint paymentPoint = paymentPointRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Ödeme noktası bulunamadı"));

            paymentPointConverter.updateEntity(paymentPoint, request);
            paymentPointRepository.save(paymentPoint);

            log.info("Payment point updated successfully by user: {}", username);
            return ResponseMessage.builder()
                    .isSuccess(true)
                    .message("Ödeme noktası başarıyla güncellendi")
                    .build();
        } catch (Exception e) {
            log.error("Error updating payment point by user: {}", username, e);
            return ResponseMessage.builder()
                    .isSuccess(false)
                    .message("Ödeme noktası güncellenirken hata oluştu: " + e.getMessage())
                    .build();
        }
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PaymentPointDTO> getById(Long id, String username) {
        try {
            PaymentPoint paymentPoint = paymentPointRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Ödeme noktası bulunamadı"));

            PaymentPointDTO dto = paymentPointConverter.toDto(paymentPoint);

            return new DataResponseMessage<>(
                    "Ödeme noktası başarıyla getirildi",
                    true,
                    dto
            );
        } catch (Exception e) {
            log.error("Error getting payment point by id for user: {}", username, e);
            return new DataResponseMessage<>(
                    "Ödeme noktası getirilirken hata oluştu: " + e.getMessage(),
                    false,
                    null
            );
        }
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<PaymentPointDTO>> getAll(String username, Pageable pageable) {
        try {
            Page<PaymentPoint> paymentPoints = paymentPointRepository.findAll(pageable);
            Page<PaymentPointDTO> dtoPage = paymentPoints.map(paymentPointConverter::toDto);
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Ödeme noktaları başarıyla getirildi",
                    true,
                    pageDTO
            );
        } catch (Exception e) {
            log.error("Error getting all payment points for user: {}", username, e);
            return new DataResponseMessage<>(
                    "Ödeme noktaları getirilirken hata oluştu: " + e.getMessage(),
                    false,
                    null
            );
        }
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<PaymentPointDTO>> getNearby(double latitude, double longitude, double radiusKm, String username, Pageable pageable) {
        try {
            Page<PaymentPoint> paymentPoints = paymentPointRepository.findNearbyPaymentPoints(
                    latitude, longitude, radiusKm, pageable
            );

            Page<PaymentPointDTO> dtoPage = paymentPoints.map(paymentPointConverter::toDto);
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Yakındaki ödeme noktaları başarıyla getirildi",
                    true,
                    pageDTO
            );
        } catch (Exception e) {
            log.error("Error getting nearby payment points for user: {}", username, e);
            return new DataResponseMessage<>(
                    "Yakındaki ödeme noktaları getirilirken hata oluştu: " + e.getMessage(),
                    false,
                    null
            );
        }
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<PaymentPointDTO>> search(PaymentPointSearchRequest searchRequest, String username, Pageable pageable) {
        try {
            Page<PaymentPoint> paymentPoints = paymentPointRepository.searchPaymentPoints(
                    searchRequest.getLatitude(),
                    searchRequest.getLongitude(),
                    searchRequest.getRadiusKm(),
                    searchRequest.getName(),
                    searchRequest.getCity(),
                    searchRequest.getDistrict(),
                    searchRequest.getPaymentMethods(),
                    searchRequest.getActive(),
                    pageable
            );

            Page<PaymentPointDTO> dtoPage = paymentPoints.map(paymentPointConverter::toDto);
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Arama sonuçları başarıyla getirildi",
                    true,
                    pageDTO
            );
        } catch (Exception e) {
            log.error("Error searching payment points for user: {}", username, e);
            throw e; // rollback olursa düzgün rollback olur
        }
    }


    @Override
    public ResponseMessage toggleStatus(Long id, boolean active, String username) {
        try {
            PaymentPoint paymentPoint = paymentPointRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Ödeme noktası bulunamadı"));

            paymentPoint.setActive(active);
            paymentPointRepository.save(paymentPoint);

            log.info("Payment point status changed to {} by user: {}", active, username);
            return ResponseMessage.builder()
                    .isSuccess(true)
                    .message("Ödeme noktası durumu başarıyla güncellendi")
                    .build();
        } catch (Exception e) {
            log.error("Error toggling payment point status by user: {}", username, e);
            return ResponseMessage.builder()
                    .isSuccess(false)
                    .message("Ödeme noktası durumu güncellenirken hata oluştu: " + e.getMessage())
                    .build();
        }
    }

    @Override
    public ResponseMessage addPhotos(Long id, List<MultipartFile> files, String username) {
        try {
            PaymentPoint paymentPoint = paymentPointRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Ödeme noktası bulunamadı"));

            List<CompletableFuture<PaymentPhoto>> futures = files.stream()
                    .map(file -> {
                                try {
                                    return fileUploadService.uploadAndOptimizeMedia(file)
                                            .thenApply(imageUrl -> {
                                                PaymentPhoto photo = new PaymentPhoto();
                                                photo.setImageUrl(imageUrl);
                                                photo.setPaymentPoint(paymentPoint);
                                                return photo;
                                            });
                                } catch (IOException | VideoSizeLargerException | OnlyPhotosAndVideosException
                                         | PhotoSizeLargerException | FileFormatCouldNotException e) {
                                    throw new RuntimeException(e);
                                }
                            }
                    )
                    .collect(Collectors.toList());

            // Tüm CompletableFuture'lar tamamlanana kadar bekle
            List<PaymentPhoto> photos = futures.stream()
                    .map(CompletableFuture::join)
                    .toList();

            paymentPoint.getPhotos().addAll(photos);
            paymentPointRepository.save(paymentPoint);

            log.info("Photos added to payment point by user: {}", username);
            return ResponseMessage.builder()
                    .isSuccess(true)
                    .message("Fotoğraflar başarıyla eklendi")
                    .build();
        } catch (Exception e) {
            log.error("Error adding photos to payment point by user: {}", username, e);
            return ResponseMessage.builder()
                    .isSuccess(false)
                    .message("Fotoğraflar eklenirken hata oluştu: " + e.getMessage())
                    .build();
        }
    }

    @Override
    public ResponseMessage delete(Long id, String username) {
        try {
            PaymentPoint paymentPoint = paymentPointRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Ödeme noktası bulunamadı"));

            paymentPointRepository.delete(paymentPoint);

            log.info("Payment point deleted successfully by user: {}", username);
            return ResponseMessage.builder()
                    .isSuccess(true)
                    .message("Ödeme noktası başarıyla silindi")
                    .build();
        } catch (Exception e) {
            log.error("Error deleting payment point by user: {}", username, e);
            return ResponseMessage.builder()
                    .isSuccess(false)
                    .message("Ödeme noktası silinirken hata oluştu: " + e.getMessage())
                    .build();
        }
    }

    @Override
    public ResponseMessage deletePhoto(Long id, Long photoId, String username) {
        try {
            PaymentPoint paymentPoint = paymentPointRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Ödeme noktası bulunamadı"));

            PaymentPhoto photo = paymentPoint.getPhotos().stream()
                    .filter(p -> p.getId().equals(photoId))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("Fotoğraf bulunamadı"));

            paymentPoint.getPhotos().remove(photo);
            paymentPointRepository.save(paymentPoint);

            log.info("Photo deleted from payment point by user: {}", username);
            return ResponseMessage.builder()
                    .isSuccess(true)
                    .message("Fotoğraf başarıyla silindi")
                    .build();
        } catch (Exception e) {
            log.error("Error deleting photo from payment point by user: {}", username, e);
            return ResponseMessage.builder()
                    .isSuccess(false)
                    .message("Fotoğraf silinirken hata oluştu: " + e.getMessage())
                    .build();
        }
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<PaymentPointDTO>> getByCity(String city, String username, Pageable pageable) {
        try {
            Page<PaymentPoint> paymentPoints = paymentPointRepository.findByAddress_CityContainingIgnoreCase(city, pageable);
            Page<PaymentPointDTO> dtoPage = paymentPoints.map(paymentPointConverter::toDto);
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Şehir bazlı ödeme noktaları başarıyla getirildi",
                    true,
                    pageDTO
            );
        } catch (Exception e) {
            log.error("Error getting payment points by city for user: {}", username, e);
            return new DataResponseMessage<>(
                    "Şehir bazlı ödeme noktaları getirilirken hata oluştu: " + e.getMessage(),
                    false,
                    null
            );
        }
    }

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<PaymentPointDTO>> getByPaymentMethod(PaymentMethod paymentMethod, String username, Pageable pageable) {
        try {
            Page<PaymentPoint> paymentPoints = paymentPointRepository.findByPaymentMethodsContaining(paymentMethod, pageable);
            Page<PaymentPointDTO> dtoPage = paymentPoints.map(paymentPointConverter::toDto);
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Ödeme yöntemi bazlı ödeme noktaları başarıyla getirildi",
                    true,
                    pageDTO
            );
        } catch (Exception e) {
            log.error("Error getting payment points by payment method for user: {}", username, e);
            return new DataResponseMessage<>(
                    "Ödeme yöntemi bazlı ödeme noktaları getirilirken hata oluştu: " + e.getMessage(),
                    false,
                    null
            );
        }
    }
}