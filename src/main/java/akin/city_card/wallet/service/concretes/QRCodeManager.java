package akin.city_card.wallet.service.concretes;

import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.wallet.core.request.QRTransferRequest;
import akin.city_card.wallet.core.response.QRCodeDTO;
import akin.city_card.wallet.service.abstracts.QRCodeService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.util.List;

@Service
public class QRCodeManager implements QRCodeService {
    @Override
    public DataResponseMessage<QRCodeDTO> generateQRCode(String username, BigDecimal amount, String description, int expirationMinutes) {
        return null;
    }

    @Override
    public DataResponseMessage<QRCodeDTO> generatePaymentQRCode(String username, String description) {
        return null;
    }

    @Override
    public DataResponseMessage<?> scanQRCode(String username, String qrData) {
        return null;
    }

    @Override
    public DataResponseMessage<?> scanQRCodeFromImage(String username, MultipartFile image) {
        return null;
    }

    @Override
    public ResponseMessage transferViaQR(String username, QRTransferRequest request) {
        return null;
    }

    @Override
    public ResponseMessage payViaQR(String username, String qrCode, BigDecimal amount, String description) {
        return null;
    }

    @Override
    public DataResponseMessage<List<QRCodeDTO>> getQRHistory(String username, int page, int size) {
        return null;
    }

    @Override
    public ResponseMessage cancelQRCode(String username, Long qrId) {
        return null;
    }
}
