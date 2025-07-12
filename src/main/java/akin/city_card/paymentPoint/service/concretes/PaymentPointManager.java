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
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.exceptions.FileFormatCouldNotException;
import akin.city_card.user.exceptions.OnlyPhotosAndVideosException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.exceptions.VideoSizeLargerException;
import akin.city_card.user.model.SearchHistory;
import akin.city_card.user.model.SearchType;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
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
    private final UserRepository userRepository;

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

            // Aktif olanları filtrele
            List<PaymentPointDTO> filteredList = paymentPoints.getContent().stream()
                    .filter(PaymentPoint::isActive)
                    .map(paymentPointConverter::toDto)
                    .toList();

            // Yeni sayfa objesi oluştur
            Page<PaymentPointDTO> dtoPage = new PageImpl<>(filteredList, pageable, filteredList.size());
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
    public DataResponseMessage<PageDTO<PaymentPointDTO>> search(PaymentPointSearchRequest searchRequest, String username, Pageable pageable) throws UserNotFoundException {
        if (username != null) {
            User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
            SearchHistory searchHistory = new SearchHistory();
            searchHistory.setUser(user);
            searchHistory.setDeleted(false);
            searchHistory.setActive(true);
            searchHistory.setSearchedAt(LocalDateTime.now());
            searchHistory.setQuery(searchRequest.getCity());
            searchHistory.setSearchType(SearchType.PAYMENT_POINT);
            user.getSearchHistory().add(searchHistory);
            userRepository.save(user);
            log.info("Search history added for user: {}", username);
        }

        try {
            // Öncelikle tüm aktif ödeme noktalarını DB'den çek (veya aktif parametre varsa ona göre filtrele)
            List<PaymentPoint> allPoints;

            if (searchRequest.getActive() != null) {
                allPoints = paymentPointRepository.findByActive(searchRequest.getActive());
            } else {
                allPoints = paymentPointRepository.findAll();
            }

            // Java'da filtreleme yap
            List<PaymentPoint> filteredPoints = allPoints.stream()
                    // Koordinat & radius kontrolü
                    .filter(pp -> {
                        if (searchRequest.getLatitude() == null || searchRequest.getLongitude() == null || searchRequest.getRadiusKm() == null) {
                            return true; // Koordinat filtreleme yoksa geç
                        }
                        double distance = haversineDistance(
                                searchRequest.getLatitude(),
                                searchRequest.getLongitude(),
                                pp.getLocation().getLatitude(),
                                pp.getLocation().getLongitude()
                        );
                        return distance <= searchRequest.getRadiusKm();
                    })
                    // İsim filtreleme
                    .filter(pp -> {
                        if (searchRequest.getName() == null || searchRequest.getName().isBlank()) return true;
                        return pp.getName().toLowerCase().contains(searchRequest.getName().toLowerCase());
                    })
                    // Şehir filtreleme
                    .filter(pp -> {
                        if (searchRequest.getCity() == null || searchRequest.getCity().isBlank()) return true;
                        return pp.getAddress().getCity() != null && pp.getAddress().getCity().toLowerCase().contains(searchRequest.getCity().toLowerCase());
                    })
                    // İlçe filtreleme
                    .filter(pp -> {
                        if (searchRequest.getDistrict() == null || searchRequest.getDistrict().isBlank()) return true;
                        return pp.getAddress().getDistrict() != null && pp.getAddress().getDistrict().toLowerCase().contains(searchRequest.getDistrict().toLowerCase());
                    })
                    // Ödeme yöntemi filtreleme
                    .filter(pp -> {
                        if (searchRequest.getPaymentMethods() == null || searchRequest.getPaymentMethods().isEmpty()) return true;
                        if (pp.getPaymentMethods() == null) return false;
                        // En az bir eşleşme yeter
                        return pp.getPaymentMethods().stream().anyMatch(searchRequest.getPaymentMethods()::contains);
                    })
                    // Çalışma saati filtrelemesini eklersin (string ise, örn: "08:00-18:00")
                    // Burada örnek olarak basit contains ile arama yapabiliriz
                    .filter(pp -> {
                        if (searchRequest.getWorkingHours() == null || searchRequest.getWorkingHours().isBlank()) return true;
                        return pp.getWorkingHours() != null && pp.getWorkingHours().contains(searchRequest.getWorkingHours());
                    })
                    .toList();

            // Sayfalama için Java Stream'den slice alalım
            int start = (int) pageable.getOffset();
            int end = Math.min((start + pageable.getPageSize()), filteredPoints.size());
            List<PaymentPointDTO> pageContent = filteredPoints.subList(start, end).stream()
                    .map(paymentPointConverter::toDto)
                    .toList();

            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(
                    new PageImpl<>(pageContent, pageable, filteredPoints.size())
            );

            return new DataResponseMessage<>(
                    "Arama sonuçları başarıyla getirildi",
                    true,
                    pageDTO
            );

        } catch (Exception e) {
            log.error("Error searching payment points for user: {}", username, e);
            throw e;
        }
    }

    /**
     * Haversine mesafe hesaplama (km cinsinden)
     */
    private double haversineDistance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371; // Dünya yarıçapı km
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
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
    @Transactional
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

    @Override
    @Transactional(readOnly = true)
    public DataResponseMessage<PageDTO<PaymentPointDTO>> getNearby(double latitude, double longitude, double radiusKm, String username, Pageable pageable) {
        try {
            // Repo'dan sayfalı veriyi çek
            Page<PaymentPoint> paymentPoints = paymentPointRepository.findNearbyPaymentPoints(latitude, longitude, radiusKm, pageable);

            // DTO dönüştür
            Page<PaymentPointDTO> dtoPage = paymentPoints.map(paymentPointConverter::toDto);
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Yakındaki ödeme noktaları başarıyla getirildi",
                    true,
                    pageDTO
            );
        } catch (Exception e) {
            log.error("Yakındaki ödeme noktaları getirilirken hata oluştu, kullanıcı: {}", username, e);
            return new DataResponseMessage<>(
                    "Yakındaki ödeme noktaları getirilirken hata oluştu: " + e.getMessage(),
                    false,
                    null
            );
        }
    }

}