package akin.city_card.wallet.model;


public enum TransactionType {
    LOAD,           // Cüzdana para yükleme
    RIDE,           // Ulaşımda harcama
    TRANSFER_OUT,   // Başka kullanıcıya gönderim
    TRANSFER_IN,    // Başka kullanıcıdan gelen
    REFUND,         // İade işlemi
    ADJUSTMENT      // Manuel bakiye düzeltme (destek vs.)
}
