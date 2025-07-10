package akin.city_card.paymentPoint.service.abstracts;

import akin.city_card.paymentPoint.core.request.AddPaymentPointRequest;
import akin.city_card.paymentPoint.core.request.PaymentPointSearchRequest;
import akin.city_card.paymentPoint.core.request.UpdatePaymentPointRequest;
import akin.city_card.paymentPoint.core.response.PaymentPointDTO;
import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import com.twilio.twiml.voice.Pay;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface PaymentPointService {

    ResponseMessage add(AddPaymentPointRequest request, String username);

    ResponseMessage update(Long id, UpdatePaymentPointRequest request, String username);

    DataResponseMessage<PaymentPointDTO> getById(Long id, String username);

    DataResponseMessage<Page<PaymentPointDTO>> getAll(String username, Pageable pageable);

    DataResponseMessage<Page<PaymentPointDTO>> search(PaymentPointSearchRequest searchRequest, String username, Pageable pageable);

    DataResponseMessage<Page<PaymentPointDTO>> getNearby(double latitude, double longitude, double radiusKm, String username, Pageable pageable);

    ResponseMessage toggleStatus(Long id, boolean active, String username);

    ResponseMessage delete(Long id, String username);

    ResponseMessage addPhotos(Long id, List<MultipartFile> files, String username);

    ResponseMessage deletePhoto(Long id, Long photoId, String username);

    DataResponseMessage<Page<PaymentPointDTO>> getByCity(String city, String username, Pageable pageable);

    DataResponseMessage<Page<PaymentPointDTO>> getByPaymentMethod(PaymentMethod paymentMethod, String username, Pageable pageable);
}
