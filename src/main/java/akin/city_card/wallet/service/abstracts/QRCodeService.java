package akin.city_card.wallet.service.abstracts;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.wallet.core.request.QRTransferRequest;
import akin.city_card.wallet.core.response.QRCodeDTO;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.util.List;

public interface QRCodeService {
    DataResponseMessage<QRCodeDTO> generateQRCode(String username, BigDecimal amount, String description, int expirationMinutes);

    DataResponseMessage<QRCodeDTO> generatePaymentQRCode(String username, String description);


    DataResponseMessage<?> scanQRCode(String username, String qrData);


    DataResponseMessage<?> scanQRCodeFromImage(String username, MultipartFile image);


    ResponseMessage transferViaQR(String username, QRTransferRequest request);


    ResponseMessage payViaQR(String username, String qrCode, BigDecimal amount, String description);

    DataResponseMessage<List<QRCodeDTO>> getQRHistory(String username, int page, int size);


    ResponseMessage cancelQRCode(String username, Long qrId);
}

