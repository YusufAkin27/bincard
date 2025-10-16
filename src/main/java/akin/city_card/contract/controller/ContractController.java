package akin.city_card.contract.controller;

import akin.city_card.contract.core.request.AcceptContractRequest;
import akin.city_card.contract.core.request.RejectContractRequest;
import akin.city_card.contract.core.response.AcceptedContractDTO;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.exceptions.ContractNotFoundException;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Kullanıcıya özel sözleşme işlemleri
 * Authentication gerektiren endpoint'ler
 */
@RestController
@RequestMapping("/v1/api/contract")
@RequiredArgsConstructor
public class ContractController {
    private final ContractService contractService;

    /**
     * Kullanıcının tüm sözleşmelerini getir (kabul durumu bilgisi ile)
     */
    @GetMapping("/contracts")
    public ResponseEntity<List<UserContractDTO>> getUserContracts(
            @AuthenticationPrincipal UserDetails userDetails
    ) throws UserNotFoundException {
        List<UserContractDTO> contracts = contractService.getUserContracts(userDetails.getUsername());
        return ResponseEntity.ok(contracts);
    }

    /**
     * Kullanıcının zorunlu sözleşmelerini getir
     * bunu kayıt olurken kullanıcının önüne getir hangi zorunlu sözleşmeler var göster
     */
    @GetMapping("/contracts/mandatory")
    public ResponseEntity<List<UserContractDTO>> getMandatoryContracts(
            @AuthenticationPrincipal UserDetails userDetails
    ) throws UserNotFoundException {
        List<UserContractDTO> contracts = contractService.getMandatoryContractsForUser(userDetails.getUsername());
        return ResponseEntity.ok(contracts);
    }

    /**
     * Kullanıcının bekleyen (kabul edilmemiş) sözleşmelerini getir
     */
    @GetMapping("/contracts/pending")
    public ResponseEntity<List<UserContractDTO>> getPendingContracts(
            @AuthenticationPrincipal UserDetails userDetails
    ) throws UserNotFoundException {
        List<UserContractDTO> contracts = contractService.getPendingContractsForUser(userDetails.getUsername());
        return ResponseEntity.ok(contracts);
    }

    /**
     * Sözleşme onaylama
     */
    @PostMapping("/contracts/{contractId}/accept")
    public ResponseEntity<ResponseMessage> acceptContract(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long contractId,
            @Valid @RequestBody AcceptContractRequest request,
            HttpServletRequest httpRequest
    ) {
        // IP ve User-Agent bilgilerini request'e ekle
        String ipAddress = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        request.setIpAddress(ipAddress);
        request.setUserAgent(userAgent);

        ResponseMessage result = contractService.acceptContract(
                userDetails.getUsername(),
                contractId,
                request
        );
        return ResponseEntity.ok(result);
    }

    /**
     * Sözleşme reddetme
     */
    @PostMapping("/contracts/{contractId}/reject")
    public ResponseEntity<ResponseMessage> rejectContract(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long contractId,
            @Valid @RequestBody RejectContractRequest request
    ) {
        ResponseMessage result = contractService.rejectContract(
                userDetails.getUsername(),
                contractId,
                request
        );
        return ResponseEntity.ok(result);
    }

    /**
     * Kullanıcının kabul ettiği sözleşmeleri görüntüleme
     */
    @GetMapping("/contracts/accepted")
    public ResponseEntity<List<AcceptedContractDTO>> getAcceptedContracts(
            @AuthenticationPrincipal UserDetails userDetails
    ) throws UserNotFoundException {
        List<AcceptedContractDTO> acceptedContracts = contractService.getUserAcceptedContracts(
                userDetails.getUsername()
        );
        return ResponseEntity.ok(acceptedContracts);
    }

    /**
     * Kullanıcının belirli bir sözleşmeyi kabul edip etmediğini kontrol et
     */
    @GetMapping("/contracts/{contractId}/acceptance-status")
    public ResponseEntity<Boolean> checkContractAcceptanceStatus(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long contractId
    ) throws UserNotFoundException, ContractNotFoundException {
        boolean isAccepted = contractService.hasUserAcceptedContract(
                userDetails.getUsername(),
                contractId
        );
        return ResponseEntity.ok(isAccepted);
    }

    /**
     * Kullanıcının tüm zorunlu sözleşmeleri kabul edip etmediğini kontrol et
     */
    @GetMapping("/contracts/mandatory/acceptance-status")
    public ResponseEntity<Boolean> checkMandatoryContractsAcceptanceStatus(
            @AuthenticationPrincipal UserDetails userDetails
    ) throws UserNotFoundException {
        boolean allAccepted = contractService.hasUserAcceptedAllMandatoryContracts(
                userDetails.getUsername()
        );
        return ResponseEntity.ok(allAccepted);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}