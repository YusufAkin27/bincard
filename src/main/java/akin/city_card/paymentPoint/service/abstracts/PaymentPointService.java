package akin.city_card.paymentPoint.service.abstracts;

import akin.city_card.news.core.response.PageDTO;
import akin.city_card.paymentPoint.core.request.AddPaymentPointRequest;
import akin.city_card.paymentPoint.core.request.UpdatePaymentPointRequest;
import akin.city_card.paymentPoint.core.response.PaymentPointDTO;
import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface PaymentPointService {
    ResponseMessage add(AddPaymentPointRequest request, String username);

    ResponseMessage update(Long id, UpdatePaymentPointRequest request, String username);

    DataResponseMessage<PaymentPointDTO> getById(Long id, String username);

    DataResponseMessage<PageDTO<PaymentPointDTO>> getAll(String username, Pageable pageable);

    ResponseMessage toggleStatus(Long id, boolean active, String username);

    ResponseMessage addPhotos(Long id, List<MultipartFile> files, String username);

    ResponseMessage delete(Long id, String username);

    ResponseMessage deletePhoto(Long id, Long photoId, String username);

    DataResponseMessage<PageDTO<PaymentPointDTO>> getByCity(String city, String username, Pageable pageable);

    DataResponseMessage<PageDTO<PaymentPointDTO>> getByPaymentMethod(PaymentMethod paymentMethod, String username, Pageable pageable);

    DataResponseMessage<PageDTO<PaymentPointDTO>> getNearby(double latitude, double longitude, double radiusKm, String username, Pageable pageable);

    DataResponseMessage<PageDTO<PaymentPointDTO>> search(String query, String username, double latitude, double longitude, Pageable pageable) throws UserNotFoundException;
}