package akin.city_card.wallet.model;


public enum TransactionType {
    LOAD,           // Cüzdana para yükleme
    RIDE,           // Ulaşımda harcama
    TRANSFER_OUT,   // Başka kullanıcıya gönderim
    TRANSFER_IN,    // Başka kullanıcıdan gelen
    REFUND,         // İade işlemi
    FORCE_CREDIT,
    FORCE_DEBIT,
    AUTO_TOPUP, ADJUSTMENT      // Manuel bakiye düzeltme (destek vs.)
}
