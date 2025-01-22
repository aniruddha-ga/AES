package base_aes;
import javax.crypto.Cipher;  
import javax.crypto.SecretKey;  
import javax.crypto.SecretKeyFactory;  
import javax.crypto.spec.IvParameterSpec;  
import javax.crypto.spec.PBEKeySpec;  
import javax.crypto.spec.SecretKeySpec;  
import java.nio.charset.StandardCharsets;  
import java.security.InvalidAlgorithmParameterException;  
import java.security.InvalidKeyException;  
import java.security.NoSuchAlgorithmException;  
import java.security.spec.InvalidKeySpecException;  
import java.security.spec.KeySpec;  
import java.security.SecureRandom;
import java.util.Base64;  
import javax.crypto.BadPaddingException;  
import javax.crypto.IllegalBlockSizeException;  
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class base_aes   
{  
    /* Private variable declaration */  
    private static String SECRET_KEY = null;  
    private static String SALTVALUE = null;  
   
    /* Encryption Method */  
    public static String encrypt(String strToEncrypt)   
    {  
    try   
    {  
      /* Declare a byte array. */  
      SecureRandom secureRandom = new SecureRandom();
      byte[] iv = new byte[16]; 
      secureRandom.nextBytes(iv);
      try (FileOutputStream fos = new FileOutputStream("encrypted_data.dat")) {
            // Write the IV (16 bytes)
            fos.write(iv);
            // Write the encrypted data (ciphertext)
            fos.write(encrypted);
      } catch (IOException | Exception e) {
            e.printStackTrace();  // Print the stack trace for debugging
      }
      IvParameterSpec ivspec = new IvParameterSpec(iv);        
      /* Create factory for secret keys. */  
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
      /* PBEKeySpec class implements KeySpec interface. */  
      KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);  
      SecretKey tmp = factory.generateSecret(spec);  
      SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");  
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);  
      /* Retruns encrypted value. */  
      return Base64.getEncoder()  
.encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));  
    }   
    catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
    {  
      System.out.println("Error occured during encryption: " + e.toString());  
    }  
    return null;  
    }  
    
    /* Decryption Method */  
    public static String decrypt(String strToDecrypt)   
    {  
    try   
    {  
      /* Declare a byte array. */  
      byte[] iv = new byte[16];  

      try (FileInputStream fis = new FileInputStream("encrypted_data.dat")) {
            // Read the IV (16 bytes)
            fis.read(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

      } catch (IOException | Exception e) {
            e.printStackTrace();  // Print the stack trace for debugging
      }
      /* Create factory for secret keys. */  
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
      /* PBEKeySpec class implements KeySpec interface. */  
      KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);  
      SecretKey tmp = factory.generateSecret(spec);  
      SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");  
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);  
      /* Retruns decrypted value. */  
      return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));  
    }   
    catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
    {  
      System.out.println("Error occured during decryption: " + e.toString());  
    }  
    return null;  
    }  
    /* Driver Code */  
    public static void main(String[] args)   
    {  
        /* Message to be encrypted. */  
        Scanner scanner = new Scanner(System.in);

        // Prompt the user for a secret key
        System.out.print("Enter the secret key: ");
        String secretKeyInput = scanner.nextLine();

        // Prompt the user for a salt value
        System.out.print("Enter the salt value: ");
        String saltValueInput = scanner.nextLine();

        // Prompt the user for a message
        System.out.print("Enter the message: ");
        String message = scanner.nextLine();

        // Print the user input for confirmation (optional)
        System.out.println("\n--- User Input Summary ---");
        System.out.println("Secret Key: " + secretKey);
        System.out.println("Salt Value: " + saltValue);
        System.out.println("Message: " + message);

        // Close the scanner
        scanner.close();

        SECRET_KEY = secretKeyInput;
        SALTVALUE = saltValueInput;
        /* Call the encrypt() method and store result of encryption. */  
        String encryptedval = encrypt(message);  
        /* Call the decrypt() method and store result of decryption. */  
        String decryptedval = decrypt(encryptedval);  
        /* Display the original message, encrypted message and decrypted message on the console. */  
        System.out.println("Original message: " + message);  
        System.out.println("Encrypted message: " + encryptedval);  
        System.out.println("Decrypted message: " + decryptedval);  
    }  
}  

