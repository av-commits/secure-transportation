package ch.avcommits.securetransportation;

import lombok.Data;

import java.time.LocalDate;

@Data
public class CardCredentialDetail {
    private String cardID;
    private String pan;
    private String validTo;
    private String embosserName;
    private String encryptedPan;
}
