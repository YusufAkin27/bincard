package akin.city_card.wallet.model;


public enum TransactionType {
    LOAD,           // Cüzdana para yükleme
    RIDE,           // Ulaşımda harcama
    WITHDRAW,   // Başka kullanıcıya gönderim
    DEPOSIT,    // Başka kullanıcıdan gelen
    REFUND,         // İade işlemi
    ADJUSTMENT      // Manuel bakiye düzeltme (destek vs.)
}
