package akin.city_card.wallet.core.converter;

import akin.city_card.wallet.core.response.TransferDetailsDTO;
import akin.city_card.wallet.core.response.WalletActivityDTO;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletActivity;
import akin.city_card.wallet.model.WalletTransfer;
import akin.city_card.wallet.repository.WalletTransactionRepository;
import akin.city_card.wallet.repository.WalletTransferRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class WalletConverterImpl implements WalletConverter {
    private final WalletTransactionRepository walletTransactionRepository;
    private final WalletTransferRepository walletTransferRepository;

    @Override
    public WalletDTO convertToDTO(Wallet wallet) {
        if (wallet == null) {
            return null;
        }

        return WalletDTO.builder()
                .walletId(wallet.getId())
                .userId(wallet.getUser() != null ? wallet.getUser().getId() : null)
                .currency(wallet.getCurrency())
                .balance(wallet.getBalance())
                .status(wallet.getStatus())
                .activeTransferCode(wallet.getActiveTransferCode())
                .transferCodeExpiresAt(wallet.getTransferCodeExpiresAt())
                .totalTransactionCount(wallet.getTotalTransactionCount())
                .createdAt(wallet.getCreatedAt()) // AuditableEntity'den miras alıyor
                .lastUpdated(wallet.getLastUpdated())
                .build();
    }

    @Override
    public TransferDetailsDTO convertToTransferDTO(WalletTransfer walletTransfer) {
        if (walletTransfer == null) {
            return null;
        }

        return TransferDetailsDTO.builder()
                .id(walletTransfer.getId())
                .amount(walletTransfer.getAmount())
                .status(walletTransfer.getStatus().name())
                .initiatedAt(walletTransfer.getInitiatedAt())
                .completedAt(walletTransfer.getCompletedAt())
                .description(walletTransfer.getDescription())
                .initiatedByUserId(walletTransfer.getInitiatedByUserId())
                .cancellationReason(walletTransfer.getCancellationReason())
                .senderWalletId(walletTransfer.getSenderWallet() != null ? walletTransfer.getSenderWallet().getId() : null)
                .receiverWalletId(walletTransfer.getReceiverWallet() != null ? walletTransfer.getReceiverWallet().getId() : null)
                .build();
    }


    @Override
    public WalletActivityDTO convertWalletActivityDTO(WalletActivity walletActivity) {
        WalletActivityDTO.WalletActivityDTOBuilder dtoBuilder = WalletActivityDTO.builder()
                .id(walletActivity.getId())
                .activityType(walletActivity.getActivityType())
                .activityDate(walletActivity.getActivityDate())
                .description(walletActivity.getDescription())
                .walletId(walletActivity.getWalletId())
                .transactionId(walletActivity.getTransactionId())
                .transferId(walletActivity.getTransferId());

        // İşlem tipi, tutar ve durumunu çek
        if (walletActivity.getTransactionId() != null) {
            walletTransactionRepository.findById(walletActivity.getTransactionId()).ifPresent(tx -> {
                dtoBuilder.transactionType(tx.getType().name());
                dtoBuilder.transactionStatus(tx.getStatus().name());
                dtoBuilder.amount(tx.getAmount());
                dtoBuilder.performedBy("userId: " + tx.getUserId()); // Veya username çekilebilir
            });
        }

        if (walletActivity.getTransferId() != null) {
            walletTransferRepository.findById(walletActivity.getTransferId()).ifPresent(transfer -> {
                if (walletActivity.getTransactionId() == null) {
                    dtoBuilder.amount(transfer.getAmount());
                }

                dtoBuilder.performedBy("userId: " + transfer.getInitiatedByUserId());
            });
        }


        return dtoBuilder.build();
    }



}
