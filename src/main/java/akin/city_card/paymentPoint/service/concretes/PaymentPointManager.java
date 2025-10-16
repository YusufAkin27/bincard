package akin.city_card.paymentPoint.service.concretes;

import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.location.model.Location;
import akin.city_card.news.core.response.PageDTO;
import akin.city_card.paymentPoint.core.converter.PaymentPointConverter;
import akin.city_card.paymentPoint.core.request.AddPaymentPointRequest;
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
import akin.city_card.security.repository.SecurityUserRepository;
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
import java.time.LocalTime;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PaymentPointManager implements PaymentPointService {

    private final PaymentPointRepository paymentPointRepository;
    private final PaymentPointConverter paymentPointConverter;
    private final MediaUploadService fileUploadService;
    private final UserRepository userRepository;
    private final SecurityUserRepository securityUserRepository;

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

            List<PaymentPointDTO> filteredList = paymentPoints.getContent().stream()
                    .map(paymentPointConverter::toDto)
                    .toList();

            Page<PaymentPointDTO> dtoPage = new PageImpl<>(filteredList, pageable, filteredList.size());
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Yakın ödeme noktaları başarıyla getirildi",
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
    public DataResponseMessage<PageDTO<PaymentPointDTO>> search(String query, String username, double latitude, double longitude, Pageable pageable) throws UserNotFoundException {
        try {
            Location baseLocation = null;

            // 1. Kullanıcı giriş yaptıysa son konumu alınır
            if (username != null && !username.isBlank()) {
                Optional<User> optionalUser = userRepository.findByUserNumber(username);

                if (optionalUser.isPresent()) {
                    User user = optionalUser.get();

                    // 1.1 Kullanıcının en son konumu varsa onu al
                    baseLocation = user.getLocationHistory().stream()
                            .max(Comparator.comparing(Location::getRecordedAt))
                            .orElse(null);

                    // 1.2 Arama geçmişine kaydet
                    if (query != null && !query.isBlank()) {
                        SearchHistory history = SearchHistory.builder()
                                .user(user)
                                .query(query)
                                .searchType(SearchType.PAYMENT_POINT)
                                .searchedAt(LocalDateTime.now())
                                .deleted(false)
                                .active(true)
                                .build();
                        user.getSearchHistory().add(history);
                        userRepository.save(user);
                        log.info("Search history saved for user: {}", username);
                    }
                } else {
                    throw new UserNotFoundException();
                }
            }

            // 2. Eğer giriş yapılmamışsa veya kullanıcı konumu yoksa gelen enlem-boylam kullanılır
            if (baseLocation == null) {
                baseLocation = new Location(); // Constructor varsa doğrudan, yoksa setter ile oluştur
                baseLocation.setLongitude(longitude);
                baseLocation.setLatitude(latitude);
            }

            List<PaymentPoint> allPoints = paymentPointRepository.findByActive(true);
            LocalTime now = LocalTime.now();

            Location finalBaseLocation = baseLocation;
            List<PaymentPoint> filtered = allPoints.stream()
                    .filter(pp -> isOpenNow(pp.getWorkingHours(), now))

                    .filter(pp -> {
                        double distance = haversineDistance(
                                finalBaseLocation.getLatitude(),
                                finalBaseLocation.getLongitude(),
                                pp.getLocation().getLatitude(),
                                pp.getLocation().getLongitude()
                        );
                        return distance <= 10.0;
                    })

                    // 4.3 Arama query'sine uyan noktalar
                    .filter(pp -> {
                        if (query == null || query.isBlank()) return true;
                        String q = query.toLowerCase();

                        return (pp.getName() != null && pp.getName().toLowerCase().contains(q)) ||
                                (pp.getWorkingHours() != null && pp.getWorkingHours().toLowerCase().contains(q)) ||
                                (pp.getDescription() != null && pp.getDescription().toLowerCase().contains(q)) ||
                                (pp.getContactNumber() != null && pp.getContactNumber().toLowerCase().contains(q)) ||
                                (pp.getAddress() != null && (
                                        (pp.getAddress().getCity() != null && pp.getAddress().getCity().toLowerCase().contains(q)) ||
                                                (pp.getAddress().getDistrict() != null && pp.getAddress().getDistrict().toLowerCase().contains(q)) ||
                                                (pp.getAddress().getStreet() != null && pp.getAddress().getStreet().toLowerCase().contains(q)) ||
                                                (pp.getAddress().getPostalCode() != null && pp.getAddress().getPostalCode().toLowerCase().contains(q))
                                ));
                    })
                    .toList();

            // 5. Sayfalama
            int start = (int) pageable.getOffset();
            int end = Math.min(start + pageable.getPageSize(), filtered.size());

            List<PaymentPointDTO> content = filtered.subList(start, end).stream()
                    .map(paymentPointConverter::toDto)
                    .toList();

            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(
                    new PageImpl<>(content, pageable, filtered.size())
            );

            return new DataResponseMessage<>(
                    "Yakındaki ve şu an açık ödeme noktaları başarıyla getirildi.",
                    true,
                    pageDTO
            );

        } catch (Exception e) {
            log.error("Arama sırasında hata oluştu. Kullanıcı: {}", username, e);
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
                    .map(file -> CompletableFuture.supplyAsync(() -> {
                        try {
                            String imageUrl = fileUploadService.uploadAndOptimizeMedia(file);
                            PaymentPhoto photo = new PaymentPhoto();
                            photo.setImageUrl(imageUrl);
                            photo.setPaymentPoint(paymentPoint);
                            return photo;
                        } catch (IOException | VideoSizeLargerException | OnlyPhotosAndVideosException
                                 | PhotoSizeLargerException | FileFormatCouldNotException e) {
                            throw new CompletionException(e); // CompletableFuture zincirine uygun exception
                        }
                    }))
                    .toList();


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
            Page<PaymentPoint> paymentPoints = paymentPointRepository.findNearbyPaymentPoints(latitude, longitude, radiusKm, pageable);

            LocalTime now = LocalTime.now();

            List<PaymentPoint> activeNowList = paymentPoints.stream()
                    .filter(PaymentPoint::isActive) // veritabanındaki 'active' kontrolü
                    .filter(pp -> isOpenNow(pp.getWorkingHours(), now))
                    .toList();

            Page<PaymentPoint> filteredPage = new PageImpl<>(activeNowList, pageable, activeNowList.size());

            Page<PaymentPointDTO> dtoPage = filteredPage.map(paymentPointConverter::toDto);
            PageDTO<PaymentPointDTO> pageDTO = new PageDTO<>(dtoPage);

            return new DataResponseMessage<>(
                    "Şu anda açık olan yakındaki ödeme noktaları başarıyla getirildi",
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

    private boolean isOpenNow(String workingHours, LocalTime now) {
        try {
            if (workingHours == null || !workingHours.contains("-")) return false;

            String[] parts = workingHours.split("-");
            if (parts.length != 2) return false;

            LocalTime start = LocalTime.parse(parts[0].trim());
            LocalTime end = LocalTime.parse(parts[1].trim());

            if (end.isBefore(start)) {
                return now.isAfter(start) || now.isBefore(end);
            }

            return !now.isBefore(start) && !now.isAfter(end); // start <= now <= end
        } catch (Exception e) {
            log.warn("Çalışma saatleri parse edilemedi: '{}'", workingHours, e);
            return false;
        }
    }

}

