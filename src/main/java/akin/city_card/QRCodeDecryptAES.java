package akin.city_card;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Logger;

@Slf4j
public class QRCodeDecryptAES { // İsim değişmedi ama artık HMAC kontrolü yapılıyor

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public String fromHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            return "";
        }
        // Boşlukları kaldır, sadece Hex karakterler kalsın
        hex = hex.replaceAll("[^0-9a-fA-F]", "");

        if (hex.length() % 2 != 0) {
            // Tek sayıda karakter gelirse hata fırlatılabilir veya son karakter atılabilir
            hex = hex.substring(0, hex.length() - 1);
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            // Hex'ten byte'a çevir
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        // Bayt dizisini UTF-8 string'e çevir (Bu, Base64 formatında HMAC.DATA stringini verecektir)
        return new String(bytes, StandardCharsets.UTF_8);
    }
    public static String decryptBase64(String qrData, String passphrase) throws Exception {
        if (qrData == null || qrData.isEmpty()) {
            throw new IllegalArgumentException("QR veri boş olamaz!");
        }

        // Veriyi HMAC ve JSON_Base64 olarak ayır
        // Veri, "HMAC.DATA" formatında beklenir ve nokta (.) ayırıcı olarak kullanılır.
        String[] parts = qrData.split("\\.", 2);

        if (parts.length != 2) {
            throw new IllegalArgumentException("Geçersiz QR veri formatı! Veri, HMAC.DATA formatında olmalıdır.");
        }

        String receivedHmacBase64 = parts[0];
        String dataBase64 = parts[1];

        // 1. Veriyi Base64'ten çözerek orijinal JSON baytlarına ulaş
        byte[] payloadBytes;
        try {
            payloadBytes = Base64.getDecoder().decode(dataBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Base64 çözme (decode) hatası: JSON kısmı geçersiz Base64 formatında.", e);
        }

        // 2. Alınan HMAC'i Base64'ten çöz
        byte[] receivedHmac;
        try {
            receivedHmac = Base64.getDecoder().decode(receivedHmacBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Base64 çözme (decode) hatası: HMAC kısmı geçersiz Base64 formatında.", e);
        }

        // 3. Orijinal veri üzerinden HMAC'i yeniden oluştur
        byte[] calculatedHmac = createHmac(payloadBytes, passphrase);

        // 4. HMAC Kontrolü: Alınan imza ile hesaplanan imza eşleşmeli
        if (!Arrays.equals(receivedHmac, calculatedHmac)) {
            // Güvenlik Uyarısı: Kurcalanma tespit edildi!
            throw new SecurityException("Veri bütünlüğü kontrolü BAŞARISIZ! HMAC imzaları eşleşmiyor. QR kod kurcalanmış olabilir.");
        }

        // 5. Kontrol başarılı, JSON'u döndür
        return new String(payloadBytes, StandardCharsets.UTF_8);
    }

    /**
     * Verinin gizli anahtar ile HMAC imzasını oluşturur.
     */
    private static byte[] createHmac(byte[] data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(secretKey);
        return mac.doFinal(data);
    }
}