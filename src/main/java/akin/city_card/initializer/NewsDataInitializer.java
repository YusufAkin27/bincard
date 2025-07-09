package akin.city_card.initializer;

import akin.city_card.news.model.*;
import akin.city_card.news.repository.NewsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;

@Component
@RequiredArgsConstructor
public class NewsDataInitializer implements ApplicationRunner {

    private final NewsRepository newsRepository;

    private static final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        if (newsRepository.count() == 0) {
            List<News> newsList = IntStream.range(0, 10)
                    .mapToObj(i -> generateRandomNews(i))
                    .toList();
            newsRepository.saveAll(newsList);
            System.out.println(">> 10 random haber eklendi.");
        }
    }

    private News generateRandomNews(int index) {
        return News.builder()
                .title("Örnek Başlık " + index)
                .content("Bu bir örnek içeriktir. " + index)
                .image("https://example.com/image" + index + ".jpg")
                .startDate(LocalDateTime.now().minusDays(random.nextInt(5)))
                .endDate(LocalDateTime.now().plusDays(random.nextInt(10) + 1))
                .active(true)
                .platform(randomEnum(PlatformType.class))
                .priority(randomEnum(NewsPriority.class))
                .type(randomEnum(NewsType.class))
                .viewCount(random.nextInt(500))
                .allowFeedback(random.nextBoolean())
                .build();
    }

    private <T extends Enum<?>> T randomEnum(Class<T> clazz) {
        T[] values = clazz.getEnumConstants();
        return values[random.nextInt(values.length)];
    }
}
