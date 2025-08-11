package akin.city_card.report.core.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SatisfactionStatsDTO {
    
    // Toplam puanlanan şikayet sayısı
    private long totalRatedReports;
    
    // Toplam puanlanabilir şikayet sayısı
    private long totalRateableReports;
    
    // Ortalama memnuniyet puanı
    private double averageRating;
    
    // Puan dağılımı
    private long rating1Count; // 1 puan
    private long rating2Count; // 2 puan
    private long rating3Count; // 3 puan
    private long rating4Count; // 4 puan
    private long rating5Count; // 5 puan
    
    // Yüzdelik dağılım
    private double rating1Percentage;
    private double rating2Percentage;
    private double rating3Percentage;
    private double rating4Percentage;
    private double rating5Percentage;
    
    // Memnuniyet oranı (4-5 puan alanların oranı)
    private double satisfactionRate;
    
    // Kategori bazlı ortalama puanlar
    private double lostItemAverage;
    private double driverComplaintAverage;
    private double cardIssueAverage;
    private double serviceDelayAverage;
    private double otherAverage;
}