package akin.city_card.user.service.concretes;

public class PhoneNumberFormatter {

    public static String normalizeTurkishPhoneNumber(String rawPhone) {
        if (rawPhone == null) return null;

        // 1. Boşlukları, tireleri, parantezleri temizle
        String cleaned = rawPhone.replaceAll("[^0-9]", "");

        // 2. Eğer başında 0 varsa kaldır (örn: 0533...)
        if (cleaned.startsWith("0")) {
            cleaned = cleaned.substring(1);
        }

        // 3. Eğer +90 yoksa başına +90 ekle
        if (!cleaned.startsWith("90")) {
            cleaned = "90" + cleaned;
        }

        return "+" + cleaned;
    }
}
