package akin.city_card.user.model;

public enum UserStatus {
    ACTIVE,           // Aktif ve giriş yapabilir
    INACTIVE,         // Kayıtlı ama henüz aktif edilmemiş
    SUSPENDED,        // Geçici olarak sistem dışı bırakılmış
    DELETED,          // Sistemden silinmiş (soft delete olabilir)
    BANNED,           // Sistem politikaları nedeniyle yasaklanmış
    FROZEN, UNVERIFIED        // Email veya telefon doğrulaması yapılmamış
}