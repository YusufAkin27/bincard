package akin.city_card.user.service.concretes;

public class PhoneNumberFormatter {

    public static String normalizeTurkishPhoneNumber(String rawPhone) {
        if (rawPhone == null) return null;

        String digitsOnly = rawPhone.replaceAll("[^0-9]", "");

        if (digitsOnly.length() == 11 && digitsOnly.startsWith("0")) {
            digitsOnly = digitsOnly.substring(1);
        }

        if (digitsOnly.length() == 10) {
            return "+90" + digitsOnly;
        }

        if (digitsOnly.length() == 12 && digitsOnly.startsWith("90")) {
            return "+" + digitsOnly;
        }

        if (rawPhone.startsWith("+90") && digitsOnly.length() == 12) {
            return "+90" + digitsOnly.substring(2);
        }

        return null;
    }

    public static boolean PhoneValid(String phoneNumber) {
        if (phoneNumber == null) return false;

        String digitsOnly = phoneNumber.replaceAll("[^0-9]", "");

        if (digitsOnly.length() == 11 && digitsOnly.startsWith("0")) {
            return digitsOnly.matches("05[0-9]{9}");
        }

        if (digitsOnly.length() == 10 && digitsOnly.startsWith("5")) {
            return digitsOnly.matches("5[0-9]{9}");
        }

        if (digitsOnly.length() == 12 && digitsOnly.startsWith("90")) {
            return digitsOnly.matches("90[5][0-9]{9}");
        }

        if (phoneNumber.startsWith("+90") && digitsOnly.length() == 12) {
            return digitsOnly.matches("90[5][0-9]{9}");
        }

        return false;//+905336360079
    }

}
