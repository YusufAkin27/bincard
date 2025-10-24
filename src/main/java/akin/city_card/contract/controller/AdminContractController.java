package akin.city_card.contract.controller;

import akin.city_card.contract.core.request.CreateContractRequest;
import akin.city_card.contract.core.request.UpdateContractRequest;
import akin.city_card.contract.core.response.AcceptedContractDTO;
import akin.city_card.contract.core.response.ContractDTO;
import akin.city_card.contract.model.ContractType;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.response.ResponseMessage;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/admin/contract")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ADMIN_ALL') or hasAuthority('CONTRACT_ADMIN') or hasAuthority('SUPERADMIN')")
public class AdminContractController {

    private final ContractService contractService;

    /**
     * Yeni sözleşme oluşturma
     */
    @PostMapping("/contracts")
    public ResponseEntity<ResponseMessage> createContract(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody CreateContractRequest request
    ) {
        try {
            ResponseMessage result = contractService.createContract(request, userDetails.getUsername());
            return ResponseEntity.status(result.isSuccess() ? HttpStatus.CREATED : HttpStatus.BAD_REQUEST)
                    .body(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Sözleşme oluşturulurken hata oluştu: " + e.getMessage(), false));
        }
    }

    /**
     * Sözleşme güncelleme (yeni versiyon oluşturur)
     */
    @PutMapping("/contracts/{contractId}")
    public ResponseEntity<ResponseMessage> updateContract(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long contractId,
            @Valid @RequestBody UpdateContractRequest request
    ) {
        try {
            ResponseMessage result = contractService.updateContract(contractId, request, userDetails.getUsername());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Sözleşme güncellenirken hata oluştu: " + e.getMessage(), false));
        }
    }

    /**
     * Sözleşme deaktive etme
     */
    @PatchMapping("/contracts/{contractId}/deactivate")
    public ResponseEntity<ResponseMessage> deactivateContract(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long contractId
    ) {
        try {
            ResponseMessage result = contractService.deactivateContract(contractId, userDetails.getUsername());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Sözleşme deaktive edilirken hata oluştu: " + e.getMessage(), false));
        }
    }

    /**
     * Sözleşme aktive etme
     */
    @PatchMapping("/contracts/{contractId}/activate")
    public ResponseEntity<ResponseMessage> activateContract(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long contractId
    ) {
        try {
            ResponseMessage result = contractService.activateContract(contractId, userDetails.getUsername());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Sözleşme aktive edilirken hata oluştu: " + e.getMessage(), false));
        }
    }

    /**
     * Tüm sözleşmeleri listeleme
     */
    @GetMapping("/contracts")
    public ResponseEntity<List<ContractDTO>> getAllContracts() {
        try {
            List<ContractDTO> contracts = contractService.getAllContracts();
            return ResponseEntity.ok(contracts);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Aktif sözleşmeleri listeleme
     */
    @GetMapping("/contracts/active")
    public ResponseEntity<List<ContractDTO>> getActiveContracts() {
        try {
            List<ContractDTO> contracts = contractService.getActiveContracts();
            return ResponseEntity.ok(contracts);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Belirli bir sözleşmeyi getirme
     */
    @GetMapping("/contracts/{contractId}")
    public ResponseEntity<ContractDTO> getContractById(@PathVariable Long contractId) {
        try {
            ContractDTO contract = contractService.getContractById(contractId);
            return ResponseEntity.ok(contract);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Tip bazında sözleşmeleri listeleme
     */
    @GetMapping("/contracts/type/{type}")
    public ResponseEntity<List<ContractDTO>> getContractsByType(@PathVariable ContractType type) {
        try {
            List<ContractDTO> contracts = contractService.getContractsByType(type);
            return ResponseEntity.ok(contracts);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Belirli bir kullanıcının onayladığı sözleşmeleri görme
     */
    @GetMapping("/users/{username}/accepted-contracts")
    public ResponseEntity<List<AcceptedContractDTO>> getUserAcceptedContracts(@PathVariable String username) {
        try {
            List<AcceptedContractDTO> acceptedContracts = contractService.getAcceptedContracts(username);
            return ResponseEntity.ok(acceptedContracts);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Kullanıcının zorunlu sözleşmeleri onaylayıp onaylamadığını kontrol et
     */
    @GetMapping("/users/{username}/mandatory-status")
    public ResponseEntity<ResponseMessage> checkUserMandatoryStatus(@PathVariable String username) {
        try {
            boolean hasAcceptedAll = contractService.hasUserAcceptedAllMandatoryContracts(username);
            String message = hasAcceptedAll
                    ? "Kullanıcı tüm zorunlu sözleşmeleri onaylamış."
                    : "Kullanıcı henüz tüm zorunlu sözleşmeleri onaylamamış.";
            return ResponseEntity.ok(new ResponseMessage(message, hasAcceptedAll));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("Kontrol edilirken hata oluştu: " + e.getMessage(), false));
        }
    }
}