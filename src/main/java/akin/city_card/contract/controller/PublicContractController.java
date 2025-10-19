package akin.city_card.contract.controller;

import akin.city_card.contract.core.response.ContractDTO;
import akin.city_card.contract.model.ContractType;
import akin.city_card.contract.service.abstacts.ContractService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Herkese açık sözleşme API'leri
 * Authentication gerektirmeyen endpoint'ler
 */
@RestController
@RequestMapping("/v1/api/public/contracts")
@RequiredArgsConstructor
public class PublicContractController {

    private final ContractService contractService;

    /**
     * Tüm aktif sözleşmeleri getir
     */
    @GetMapping
    public ResponseEntity<List<ContractDTO>> getActiveContracts() {
        List<ContractDTO> contracts = contractService.getPublicActiveContracts();
        return ResponseEntity.ok(contracts);
    }

    /**
     * Belirli bir sözleşmeyi ID ile getir
     */
    @GetMapping("/{contractId}")
    public ResponseEntity<ContractDTO> getContractById(@PathVariable Long contractId) {
        try {
            ContractDTO contract = contractService.getPublicContractById(contractId);
            return ResponseEntity.ok(contract);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Belirli bir tip için en güncel sözleşmeyi getir
     */
    @GetMapping("/type/{contractType}")
    public ResponseEntity<ContractDTO> getLatestContractByType(@PathVariable ContractType contractType) {
        try {
            ContractDTO contract = contractService.getLatestContractByType(contractType);
            return ResponseEntity.ok(contract);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Üyelik sözleşmesinin en güncel halini getir
     */
    @GetMapping("/membership")
    public ResponseEntity<ContractDTO> getMembershipContract() {
        try {
            ContractDTO contract = contractService.getLatestContractByType(ContractType.UYELIK_SOZLESMESI);
            return ResponseEntity.ok(contract);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * KVKK Aydınlatma Metninin en güncel halini getir
     */
    @GetMapping("/kvkk-illumination")
    public ResponseEntity<ContractDTO> getKvkkIllumination() {
        try {
            ContractDTO contract = contractService.getLatestContractByType(ContractType.AYDINLATMA_METNI);
            return ResponseEntity.ok(contract);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Kişisel Veri İşleme İzni sözleşmesinin en güncel halini getir
     */
    @GetMapping("/data-processing-consent")
    public ResponseEntity<ContractDTO> getDataProcessingConsent() {
        try {
            ContractDTO contract = contractService.getLatestContractByType(ContractType.VERI_ISLEME_IZNI);
            return ResponseEntity.ok(contract);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Gizlilik Politikasının en güncel halini getir
     */
    @GetMapping("/privacy-policy")
    public ResponseEntity<ContractDTO> getPrivacyPolicy() {
        try {
            ContractDTO contract = contractService.getLatestContractByType(ContractType.GIZLILIK_POLITIKASI);
            return ResponseEntity.ok(contract);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Kullanım Koşullarının en güncel halini getir
     */
    @GetMapping("/terms-of-use")
    public ResponseEntity<ContractDTO> getTermsOfUse() {
        try {
            ContractDTO contract = contractService.getLatestContractByType(ContractType.KULLANIM_KOSULLARI);
            return ResponseEntity.ok(contract);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Mevcut tüm sözleşme tiplerini listele
     */
    @GetMapping("/types")
    public ResponseEntity<ContractType[]> getContractTypes() {
        return ResponseEntity.ok(ContractType.values());
    }
}