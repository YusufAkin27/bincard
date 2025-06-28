package akin.city_card.user.service.concretes;

public class PhoneNumberFormatter {

    /**
     * Türk telefon numaralarını normalize eder.
     * @param rawPhone Kullanıcının girdiği telefon numarası (örn: "0532 123 12 12", "+90 532 1231212")
     * @return Normalized hali (örn: "+905321231212") ya da geçersizse null
     */
    public static String normalizeTurkishPhoneNumber(String rawPhone) {
        if (rawPhone == null) return null;

        // 1. Sadece rakamları al (örn: "0532 123 12 12" => "05321231212")
        String digitsOnly = rawPhone.replaceAll("[^0-9]", "");

        // 2. Eğer 11 haneli ve 0 ile başlıyorsa (örn: 05XXXXXXXXX)
        if (digitsOnly.length() == 11 && digitsOnly.startsWith("0")) {
            digitsOnly = digitsOnly.substring(1); // baştaki 0'ı at => 5XXXXXXXXX
        }

        // 3. Eğer 10 haneli ise (örn: 5XXXXXXXXX)
        if (digitsOnly.length() == 10) {
            return "+90" + digitsOnly;
        }

        // 4. Eğer 12 haneli ve 90 ile başlıyorsa
        if (digitsOnly.length() == 12 && digitsOnly.startsWith("90")) {
            return "+" + digitsOnly;
        }

        // 5. Eğer 13 haneli ve +90 ile başlıyorsa zaten normalize edilmiş
        if (rawPhone.startsWith("+90") && digitsOnly.length() == 12) {
            return "+90" + digitsOnly.substring(2); // rawPhone zaten uygun olabilir
        }

        // Geçersiz telefon numarası (log atmak istersen buraya koyabilirsin)
        return null;
    }
    public static boolean PhoneValid(String phoneNumber) {
        if (phoneNumber == null) return false;

        // Sadece rakamları al
        String digitsOnly = phoneNumber.replaceAll("[^0-9]", "");

        // 05XXXXXXXXX (11 haneli ve 0 ile başlıyorsa)
        if (digitsOnly.length() == 11 && digitsOnly.startsWith("0")) {
            return digitsOnly.matches("05[0-9]{9}");
        }

        // 5XXXXXXXXX (10 haneli)
        if (digitsOnly.length() == 10 && digitsOnly.startsWith("5")) {
            return digitsOnly.matches("5[0-9]{9}");
        }

        // 90 ile başlayan 12 haneli
        if (digitsOnly.length() == 12 && digitsOnly.startsWith("90")) {
            return digitsOnly.matches("90[5][0-9]{9}");
        }

        // +90 ile başlayan, toplam 13 karakterli bir string
        if (phoneNumber.startsWith("+90") && digitsOnly.length() == 12) {
            return digitsOnly.matches("90[5][0-9]{9}");
        }

        return false;
    }

}
