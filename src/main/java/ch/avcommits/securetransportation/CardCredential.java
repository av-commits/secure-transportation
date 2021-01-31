package ch.avcommits.securetransportation;

import lombok.Data;

@Data
public class CardCredential {
    private String cardId;
    private String encryptedContent;
}
