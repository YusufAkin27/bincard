package akin.city_card.mail;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
@EnableAsync
public class MailAsyncConfig {

    @Bean(name = "emailTaskExecutor")
    public Executor emailTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);      // Minimum thread sayısı
        executor.setMaxPoolSize(10);      // Maksimum thread sayısı
        executor.setQueueCapacity(100);   // Kuyruk kapasitesi
        executor.setThreadNamePrefix("EmailThread-");
        executor.initialize();
        return executor;
    }
}
