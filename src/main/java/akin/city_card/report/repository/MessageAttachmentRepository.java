package akin.city_card.report.repository;

import akin.city_card.report.model.MessageAttachment;
import akin.city_card.report.model.ReportMessage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MessageAttachmentRepository extends JpaRepository<MessageAttachment, Long> {
    List<MessageAttachment> findByMessage(ReportMessage message);
}
