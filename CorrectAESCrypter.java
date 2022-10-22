
package base_aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

public class CorrectAESCrypter {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

    private static final int TAG_LENGTH_BIT = 128; // must be one of {128, 120, 112, 104, 96}
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    // return a base64 encoded AES encrypted text
    public static String encrypt(byte[] pText, String password, byte[] salt) throws Exception {

        // 16 bytes salt
//        byte[] salt = CryptoUtils.getRandomNonce(SALT_LENGTH_BYTE);

        // GCM recommended 12 bytes iv?
        byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);

        // secret key from password
        SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        // ASE-GCM needs GCMParameterSpec
        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] cipherText = cipher.doFinal(pText);

        // prefix IV and Salt to cipher text
        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();

        // string representation, base64, send this string to other for decryption.
        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);

    }

    // we need the same password, salt and iv to decrypt it
    private static String decrypt(String cText, String password,byte[] salt) throws Exception {

        byte[] decode = Base64.getDecoder().decode(cText.getBytes(UTF_8));

        // get back the iv and salt from the cipher text
        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

//        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        // get back the aes key from the same password and salt
        SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText, UTF_8);

    }

    public static void main(String[] args) throws Exception {


        String OUTPUT_FORMAT = "%-30s:%s";
        while(true){
        Scanner s = new Scanner(System.in);
        System.out.println("1: Encryption\n2: Decryption");
        System.out.print("Enter the option:");
        int opt = Integer.parseInt(s.next());
        switch(opt){
        case 1:  
            System.out.print("Enter the password for Encryption:");
            String PASSWORD_FOR_ENCRYPTION = s.next();
            System.out.print("Enter the text for Salt 7:");
            String SALT_FOR_ENC = s.next();
            System.out.print("Enter the text for Encryption:");
            s.nextLine();
            String pText =  s.nextLine();
            byte B_SALT[] = SALT_FOR_ENC.getBytes(UTF_8);
            if(B_SALT.length <= SALT_LENGTH_BYTE ){
            String encryptedText = CorrectAESCrypter.encrypt(pText.getBytes(UTF_8), PASSWORD_FOR_ENCRYPTION,B_SALT);
            System.out.println("\n------ AES GCM Password-based Encryption ------");
            System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText));
            System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (base64) ", encryptedText));
            }
            else{
            System.out.println("Enter Proper Salt");
            }
            break;
        case 2:
            System.out.print("Enter the password for Decryption:");
            String PASSWORD_FOR_DECRYPTION = s.next();
            System.out.print("Enter the Salt for Decryption:");
            String SALT_FOR_DEC = s.next();
            System.out.print("Enter the base64 text for Decryption:");
            s.nextLine();
            String encryptedTextBase64 = s.nextLine();
            byte B_DEC_SALT[] = SALT_FOR_DEC.getBytes(UTF_8);
            if(B_DEC_SALT.length <= SALT_LENGTH_BYTE){
            System.out.println("\n------ AES GCM Password-based Decryption ------");
            System.out.println(String.format(OUTPUT_FORMAT, "Input (base64)", encryptedTextBase64));
            String decryptedText = CorrectAESCrypter.decrypt(encryptedTextBase64, PASSWORD_FOR_DECRYPTION,B_DEC_SALT);
            System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));
            }
            else{
            System.out.println("Enter Proper Salt");
            }
            break;
        
        default:
                s.close();
                System.exit(0);
                break;
                }
        }
        
        
       
    }

}
    
