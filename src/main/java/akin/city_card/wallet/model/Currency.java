package akin.city_card.wallet.model;

public enum Currency {

    // Türk Lirası
    TRY("Türk Lirası"),

    // Dolar
    USD("Amerikan Doları"),
    CAD("Kanada Doları"),
    AUD("Avustralya Doları"),
    NZD("Yeni Zelanda Doları"),

    // Euro ve Avrupa para birimleri
    EUR("Euro"),
    GBP("İngiliz Sterlini"),
    CHF("İsviçre Frangı"),
    DKK("Danimarka Kronu"),
    NOK("Norveç Kronu"),
    SEK("İsveç Kronu"),

    // Asya para birimleri
    JPY("Japon Yeni"),
    CNY("Çin Yuanı"),
    KRW("Güney Kore Wonu"),
    INR("Hindistan Rupisi"),
    HKD("Hong Kong Doları"),
    SGD("Singapur Doları"),

    // Ortadoğu ve Afrika
    AED("Birleşik Arap Emirlikleri Dirhemi"),
    SAR("Suudi Riyali"),
    QAR("Katar Riyali"),
    ZAR("Güney Afrika Randı"),
    EGP("Mısır Lirası");


    private final String fullName;

    Currency(String fullName) {
        this.fullName = fullName;
    }

    public String getFullName() {
        return fullName;
    }
}
