package akin.city_card;

import com.google.zxing.*;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.Scanner;

public class QRCodeGenerateAES { // İsim değişmedi ama artık HMAC kullanılıyor

    // QR kod verisinin bütünlüğünü kontrol etmek için kullanılan gizli anahtar (Passphrase)
    public static final String SECRET_PASSPHRASE = "5de7677623ddf99c244031c1a5fbb52e212ffae70ffa7f4abbfec793b07c3c82";
    private static final int QR_SIZE = 480;
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public static void main(String[] args) throws Exception {
        System.out.println("--- QR Code Generator (HMAC Signed) ---");

        Scanner sc = new Scanner(System.in);
        System.out.print("Telefon Numarası: ");
        String phone = sc.nextLine().trim();
        System.out.print("Şifre: ");
        String password = sc.nextLine().trim();
        sc.close();

        if (phone.isEmpty() || password.isEmpty()) {
            System.err.println("Telefon numarası veya şifre boş olamaz.");
            return;
        }

        // 1. JSON oluştur
        String json = String.format("{\"phone\":\"%s\",\"password\":\"%s\"}", escapeJson(phone), escapeJson(password));
        System.out.println("Orijinal JSON verisi: " + json);

        byte[] payloadBytes = json.getBytes(StandardCharsets.UTF_8);

        // 2. JSON verisinin HMAC imzasını oluştur
        byte[] hmacSignature = createHmac(payloadBytes, SECRET_PASSPHRASE);
        String hmacBase64 = Base64.getEncoder().encodeToString(hmacSignature);

        // 3. HMAC ve JSON'u birleştir ve Base64 yap: FORMAT: HMAC_BASE64.JSON_BASE64
        // Basitlik için sadece JSON'u Base64 yapıp araya ayırıcı koyalım.
        String jsonBase64 = Base64.getEncoder().encodeToString(payloadBytes);

        // Final QR kodu içeriği: HMAC (Base64) + "." + Veri (Base64)
        String finalQRData = hmacBase64 + "." + jsonBase64;
        System.out.println("QR Verisi (HMAC.DATA): " + finalQRData);

        // 4. QR oluştur
        File out = new File(generateFileName());
        generateQr(finalQRData, QR_SIZE, QR_SIZE, out);
        System.out.println("✅ QR kod başarıyla oluşturuldu: " + out.getAbsolutePath());

        // 5. Test: Oluşturulan QR verisini çözme sınıfı ile test et
        try {
            String decrypted = QRCodeDecryptAES.decryptBase64(finalQRData, SECRET_PASSPHRASE);
            System.out.println("🔓 Test Çözme Sonucu: " + decrypted);
            if (decrypted.equals(json)) {
                System.out.println("✅ HMAC kontrolü başarılı. Veri bütünlüğü korundu.");
            } else {
                System.err.println("❌ Veri Bütünlüğü Hatası!");
            }
        } catch (Exception e) {
            System.err.println("❌ Test Çözme Hatası: " + e.getMessage());
        }
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

    private static void generateQr(String text, int width, int height, File file) throws Exception {
        QRCodeWriter writer = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H); // Yüksek hata düzeltme seviyesi
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(EncodeHintType.MARGIN, 1);
        BitMatrix matrix = writer.encode(text, BarcodeFormat.QR_CODE, width, height, hints);
        BufferedImage img = MatrixToImageWriter.toBufferedImage(matrix);
        ImageIO.write(img, "PNG", file);
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String generateFileName() {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        return "hmac_qr_" + ts + ".png";
    }
}