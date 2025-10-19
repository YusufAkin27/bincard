package akin.city_card.contract.service.concretes;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.contract.core.converter.ContractConverter;
import akin.city_card.contract.core.request.AcceptContractRequest;
import akin.city_card.contract.core.request.CreateContractRequest;
import akin.city_card.contract.core.request.RejectContractRequest;
import akin.city_card.contract.core.request.UpdateContractRequest;
import akin.city_card.contract.core.response.AcceptedContractDTO;
import akin.city_card.contract.core.response.ContractDTO;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.exceptions.AlreadyContractAcceptedException;
import akin.city_card.contract.exceptions.AlreadyContractRejectedException;
import akin.city_card.contract.exceptions.ContractNotActiveException;
import akin.city_card.contract.exceptions.ContractNotFoundException;
import akin.city_card.contract.model.Contract;
import akin.city_card.contract.model.ContractType;
import akin.city_card.contract.model.UserContractAcceptance;
import akin.city_card.contract.repository.ContractRepository;
import akin.city_card.contract.repository.UserContractAcceptanceRepository;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.repository.SecurityUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ContractManager implements ContractService {

    private final ContractRepository contractRepository;
    private final UserContractAcceptanceRepository acceptanceRepository;
    private final SecurityUserRepository securityUserRepository;
    private final ContractConverter contractConverter;

    // Admin İşlemleri
    @Override
    @Transactional
    public ResponseMessage createContract(CreateContractRequest request, String adminUsername) {
        try {
            SecurityUser admin = securityUserRepository.findByUserNumber(adminUsername)
                    .orElseThrow(AdminNotFoundException::new);

            Contract contract = Contract.builder()
                    .title(request.getTitle())
                    .content(request.getContent())
                    .version(request.getVersion())
                    .type(request.getType())
                    .mandatory(request.isMandatory())
                    .active(request.isActive())
                    .createdBy(admin)
                    .build();

            contractRepository.save(contract);

            log.info("Yeni sözleşme oluşturuldu: {} - {} tarafından", contract.getTitle(), adminUsername);
            return new ResponseMessage("Sözleşme başarıyla oluşturuldu.", true);

        } catch (Exception e) {
            log.error("Sözleşme oluşturulurken hata: ", e);
            return new ResponseMessage("Sözleşme oluşturulamadı: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage updateContract(Long contractId, UpdateContractRequest request, String adminUsername) {
        try {
            Contract existingContract = contractRepository.findById(contractId)
                    .orElseThrow(() -> new RuntimeException("Sözleşme bulunamadı"));

            SecurityUser admin = securityUserRepository.findByUserNumber(adminUsername)
                    .orElseThrow(AdminNotFoundException::new);

            // Yeni versiyon oluştur (eski veriyi korumak için)
            Contract newContract = Contract.builder()
                    .title(request.getTitle())
                    .content(request.getContent())
                    .version(request.getVersion())
                    .type(existingContract.getType())
                    .mandatory(request.isMandatory())
                    .active(request.isActive())
                    .createdBy(admin)
                    .build();

            // Eski sözleşmeyi deaktive et
            existingContract.setActive(false);
            contractRepository.save(existingContract);

            // Yeni versiyonu kaydet
            contractRepository.save(newContract);

            log.info("Sözleşme güncellendi: {} - Yeni versiyon: {} - {} tarafından",
                    newContract.getTitle(), newContract.getVersion(), adminUsername);
            return new ResponseMessage("Sözleşme başarıyla güncellendi. Yeni versiyon oluşturuldu.", true);

        } catch (Exception e) {
            log.error("Sözleşme güncellenirken hata: ", e);
            return new ResponseMessage("Sözleşme güncellenemedi: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage deactivateContract(Long contractId, String adminUsername) {
        try {
            Contract contract = contractRepository.findById(contractId)
                    .orElseThrow(() -> new RuntimeException("Sözleşme bulunamadı"));

            contract.setActive(false);
            contractRepository.save(contract);

            log.info("Sözleşme deaktive edildi: {} - {} tarafından", contract.getTitle(), adminUsername);
            return new ResponseMessage("Sözleşme başarıyla deaktive edildi.", true);

        } catch (Exception e) {
            log.error("Sözleşme deaktive edilirken hata: ", e);
            return new ResponseMessage("Sözleşme deaktive edilemedi: " + e.getMessage(), false);
        }
    }

    @Override
    @Transactional
    public ResponseMessage activateContract(Long contractId, String adminUsername) {
        try {
            Contract contract = contractRepository.findById(contractId)
                    .orElseThrow(() -> new RuntimeException("Sözleşme bulunamadı"));

            contract.setActive(true);
            contractRepository.save(contract);

            log.info("Sözleşme aktive edildi: {} - {} tarafından", contract.getTitle(), adminUsername);
            return new ResponseMessage("Sözleşme başarıyla aktive edildi.", true);

        } catch (Exception e) {
            log.error("Sözleşme aktive edilirken hata: ", e);
            return new ResponseMessage("Sözleşme aktive edilemedi: " + e.getMessage(), false);
        }
    }

    @Override
    public ContractDTO getContractById(Long contractId) {
        Contract contract = contractRepository.findById(contractId)
                .orElseThrow(() -> new RuntimeException("Sözleşme bulunamadı"));
        return contractConverter.mapToContractDTO(contract);
    }

    @Override
    public List<ContractDTO> getAllContracts() {
        return contractRepository.findAllByOrderByCreatedAtDesc()
                .stream()
                .map(contractConverter::mapToContractDTO)
                .collect(Collectors.toList());
    }

    @Override
    public List<ContractDTO> getActiveContracts() {
        return contractRepository.findByActiveOrderByCreatedAtDesc(true)
                .stream()
                .map(contractConverter::mapToContractDTO)
                .collect(Collectors.toList());
    }

    @Override
    public List<ContractDTO> getContractsByType(ContractType type) {
        return contractRepository.findByTypeAndActiveOrderByCreatedAtDesc(type, true)
                .stream()
                .map(contractConverter::mapToContractDTO)
                .collect(Collectors.toList());
    }

    // Herkese açık API metodları
    @Override
    public List<ContractDTO> getPublicActiveContracts() {
        return contractRepository.findByActiveOrderByCreatedAtDesc(true)
                .stream()
                .map(contractConverter::mapToContractDTO)
                .collect(Collectors.toList());
    }

    @Override
    public ContractDTO getLatestContractByType(ContractType type) {
        Contract contract = contractRepository.findTopByTypeAndActiveOrderByCreatedAtDesc(type, true)
                .orElseThrow(() -> new RuntimeException("Bu tip için aktif sözleşme bulunamadı: " + type));
        return contractConverter.mapToContractDTO(contract);
    }

    @Override
    public ContractDTO getPublicContractById(Long contractId) {
        Contract contract = contractRepository.findByIdAndActive(contractId, true)
                .orElseThrow(() -> new RuntimeException("Aktif sözleşme bulunamadı"));
        return contractConverter.mapToContractDTO(contract);
    }

    // Kullanıcı İşlemleri
    @Override
    public List<UserContractDTO> getUserContracts(String username) throws UserNotFoundException {
        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        List<Contract> activeContracts = contractRepository.findByActiveOrderByCreatedAtDesc(true);
        List<UserContractAcceptance> userAcceptances = acceptanceRepository.findByUser(user);

        Map<Long, UserContractAcceptance> acceptanceMap = userAcceptances.stream()
                .collect(Collectors.toMap(
                        acceptance -> acceptance.getContract().getId(),
                        acceptance -> acceptance,
                        (existing, replacement) -> replacement // En son işlemi al
                ));

        return activeContracts.stream()
                .map(contract -> contractConverter.mapToUserContractDTO(contract, acceptanceMap.get(contract.getId())))
                .collect(Collectors.toList());
    }

    @Override
    public List<UserContractDTO> getMandatoryContractsForUser(String username) throws UserNotFoundException {
        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        List<Contract> mandatoryContracts = contractRepository.findByMandatoryAndActiveOrderByCreatedAtDesc(true, true);
        List<UserContractAcceptance> userAcceptances = acceptanceRepository.findByUser(user);

        Map<Long, UserContractAcceptance> acceptanceMap = userAcceptances.stream()
                .collect(Collectors.toMap(
                        acceptance -> acceptance.getContract().getId(),
                        acceptance -> acceptance,
                        (existing, replacement) -> replacement
                ));

        return mandatoryContracts.stream()
                .map(contract -> contractConverter.mapToUserContractDTO(contract, acceptanceMap.get(contract.getId())))
                .collect(Collectors.toList());
    }

    @Override
    public List<UserContractDTO> getPendingContractsForUser(String username) throws UserNotFoundException {
        return getUserContracts(username).stream()
                .filter(contract -> contract.getUserAccepted() == null)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public ResponseMessage acceptContract(String username, Long contractId, AcceptContractRequest request) {
        try {
            SecurityUser user = securityUserRepository.findByUserNumber(username)
                    .orElseThrow(UserNotFoundException::new);

            Contract contract = contractRepository.findById(contractId)
                    .orElseThrow(ContractNotFoundException::new);

            if (!contract.isActive()) {
                throw new ContractNotActiveException();
            }

            if (acceptanceRepository.existsByUserAndContractAndAccepted(user, contract, true)) {
                throw new AlreadyContractAcceptedException();
            }

            UserContractAcceptance acceptance = buildAcceptance(user, contract, request);
            acceptanceRepository.save(acceptance);

            log.info("Sözleşme onaylandı: {} - Kullanıcı: {} - IP: {}",
                    contract.getTitle(), username, request.getIpAddress());

            return new ResponseMessage("Sözleşme başarıyla onaylandı.", true);
        } catch (Exception e) {
            log.error("Sözleşme onaylanırken hata: ", e);
            return new ResponseMessage("Sözleşme onaylanamadı: " + e.getMessage(), false);
        }
    }

    /**
     * Sözleşme kabul kaydını oluşturur.
     */
    private UserContractAcceptance buildAcceptance(SecurityUser user, Contract contract, AcceptContractRequest request) {
        return UserContractAcceptance.builder()
                .user(user)
                .contract(contract)
                .accepted(true)
                .ipAddress(request.getIpAddress())
                .userAgent(request.getUserAgent())
                .contractVersion(contract.getVersion())
                .acceptedAt(LocalDateTime.now())
                .build();
    }


    @Transactional
    @Override
    public ResponseMessage rejectContract(String username, Long contractId, RejectContractRequest request) {
        try {
            SecurityUser user = securityUserRepository.findByUserNumber(username)
                    .orElseThrow(UserNotFoundException::new);

            Contract contract = contractRepository.findById(contractId)
                    .orElseThrow(ContractNotFoundException::new);

            if (!contract.isActive()) {
                throw new ContractNotActiveException();
            }

            if (acceptanceRepository.existsByUserAndContractAndAccepted(user, contract, false)) {
                throw new AlreadyContractRejectedException();
            }

            acceptanceRepository.deleteByUserAndContractAndAccepted(user, contract, true);

            UserContractAcceptance rejection = buildRejection(user, contract, request);
            acceptanceRepository.save(rejection);

            log.info("Sözleşme reddedildi: {} - Kullanıcı: {} - Sebep: {}",
                    contract.getTitle(), username, request.getRejectionReason());

            return new ResponseMessage("Sözleşme reddetme kaydı oluşturuldu.", true);
        } catch (Exception e) {
            log.error("Sözleşme reddedilirken hata: ", e);
            return new ResponseMessage("Sözleşme reddetme işlemi başarısız: " + e.getMessage(), false);
        }
    }

    private UserContractAcceptance buildRejection(SecurityUser user, Contract contract, RejectContractRequest request) {
        return UserContractAcceptance.builder()
                .user(user)
                .contract(contract)
                .accepted(false)
                .rejectionReason(request.getRejectionReason())
                .contractVersion(contract.getVersion())
                .acceptedAt(LocalDateTime.now())
                .build();
    }


    @Override
    //admin için
    public List<AcceptedContractDTO> getAcceptedContracts(String username) throws UserNotFoundException {
        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        return acceptanceRepository.findByUserAndAcceptedOrderByAcceptedAtDesc(user, true)
                .stream()
                .map(contractConverter::mapToAcceptedContractDTO)
                .collect(Collectors.toList());
    }

    // Yeni eklenen method - Kullanıcının kabul ettiği sözleşmeleri getir
    @Override
    public List<AcceptedContractDTO> getUserAcceptedContracts(String username) throws UserNotFoundException {
        return getAcceptedContracts(username);
    }

    // Otomatik sözleşme kabul etme methodu - Kayıt sırasında kullanılacak
    @Override
    @Transactional
    public void autoAcceptMandatoryContracts(SecurityUser user, String ipAddress, String userAgent) {
        try {
            // Zorunlu ama henüz kabul edilmemiş sözleşmeleri getir
            List<Contract> unacceptedMandatoryContracts = getUnacceptedMandatoryContracts(user.getUsername());

            for (Contract contract : unacceptedMandatoryContracts) {
                UserContractAcceptance acceptance = UserContractAcceptance.builder()
                        .user(user)
                        .contract(contract)
                        .accepted(true)
                        .ipAddress(ipAddress)
                        .userAgent(userAgent)
                        .contractVersion(contract.getVersion())
                        .acceptedAt(LocalDateTime.now())
                        .build();

                acceptanceRepository.save(acceptance);

                log.info("Otomatik sözleşme kabulü: {} - Kullanıcı: {} - IP: {}",
                        contract.getTitle(), user.getUserNumber(), ipAddress);
            }
        } catch (Exception e) {
            log.error("Otomatik sözleşme kabulü sırasında hata - Kullanıcı: {}", user.getUserNumber(), e);
        }
    }


    // Kontrol İşlemleri
    @Override
    public boolean hasUserAcceptedContract(String username, Long contractId) throws UserNotFoundException, ContractNotFoundException {
        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        Contract contract = contractRepository.findById(contractId)
                .orElseThrow(ContractNotFoundException::new);

        return acceptanceRepository.existsByUserAndContractAndAccepted(user, contract, true);
    }

    @Override
    public boolean hasUserAcceptedAllMandatoryContracts(String username) throws UserNotFoundException {
        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        List<Contract> mandatoryContracts = contractRepository.findByMandatoryAndActive(true, true);

        for (Contract contract : mandatoryContracts) {
            if (!acceptanceRepository.existsByUserAndContractAndAccepted(user, contract, true)) {
                return false;
            }
        }

        return true;
    }

    @Override
    public List<Contract> getUnacceptedMandatoryContracts(String username) throws UserNotFoundException {
        SecurityUser user = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        List<Contract> mandatoryContracts = contractRepository.findByMandatoryAndActive(true, true);
        List<Contract> unacceptedContracts = new ArrayList<>();

        for (Contract contract : mandatoryContracts) {
            if (!acceptanceRepository.existsByUserAndContractAndAccepted(user, contract, true)) {
                unacceptedContracts.add(contract);
            }
        }

        return unacceptedContracts;
    }
}