package General;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class General {

    // returns 24 byte key which will be used by KDC to generate session keys
    public String giveRandomKey() {
        SecureRandom randomKey = new SecureRandom();
        byte[] randomKeyBytes = new byte[32];
        randomKey.nextBytes(randomKeyBytes);
        String randomKeyString = Base64.getUrlEncoder().withoutPadding().encodeToString(randomKeyBytes);
        return randomKeyString.substring(0, Math.min(randomKeyString.length(), 24));
    }

    // returns a 64bit nounce
    public long giveRandom() {
        Random rand = new Random();
        long nb = rand.nextLong();
        return nb;
    }

    // Encrypt using TripleDES and encode to ensure that the special characters can
    // be converted to strings.
    public String EncryptTDES(String nb, SecretKeySpec abKeySpec, IvParameterSpec abKeyivSpec) {
        String nbEncoded = "";
        try {
            Cipher encryptCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, abKeySpec, abKeyivSpec);
            byte[] nbBytes = String.valueOf(nb).getBytes(StandardCharsets.UTF_8);
            byte[] nbEncryptedBytes = encryptCipher.doFinal(nbBytes);
            nbEncoded = Base64.getEncoder().encodeToString(nbEncryptedBytes);
            return nbEncoded;
        } catch (Exception e) {
            e.printStackTrace();
            return nbEncoded;
        }
    }

    // Decode the string reeived to convert it into the encrypted value and decrypt
    // using TripleDES
    public String DecryptTDES(String nbEncoded, SecretKeySpec abKeySpec, IvParameterSpec abKeyivSpec) {
        String nbDecoded = "";
        try {
            byte[] nbEncryptedBytes = Base64.getDecoder().decode(nbEncoded);
            Cipher decryptCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, abKeySpec, abKeyivSpec);
            byte[] nbDecryptedBytes = decryptCipher.doFinal(nbEncryptedBytes);
            nbDecoded = new String(nbDecryptedBytes, StandardCharsets.UTF_8);
            return nbDecoded;
        } catch (Exception e) {
            System.out.println(
                    "The decryption failed due to improper format. Returning empty string. More details on why the decryption failed: "
                            + e.getMessage());
            return nbDecoded;
        }
    }

    public byte[] getHash(String message) {
        // Create a MessageDigest instance for SHA-1
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest((message).getBytes(StandardCharsets.UTF_8));
            System.out.println("Hash of the message is: " + new String(hash));
            return hash;
        } catch (Exception e) {
            e.printStackTrace();
            byte[] byteArray = new byte[] {};
            return (byteArray);
        }
    }

    public byte[] EncryptRSA(java.security.PublicKey publicKey, String plainText) {
        try {
            // Encrypt a message using Alice's public key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, (Key) publicKey);
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            System.out.println("Encrypted message is: " + new String(cipherText));
            return (cipherText);
        } catch (Exception e) {
            e.printStackTrace();
            byte[] byteArray = new byte[] {};
            return (byteArray);
        }
    }

    public String DecryptRSA(PrivateKey privateKey, byte[] cipherText) {
        try {
            // Decrypt the message using Alice's private key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedText = cipher.doFinal(cipherText);
            System.out.println("Decrypted message is: " + new String(decryptedText));
            return (new String(decryptedText));
        } catch (Exception e) {
            e.printStackTrace();
            String str = "";
            return (str);
        }
    }

    public void verifyHash(byte[] b1, byte[] b2) {
        if (Arrays.equals(b1, b2)) {
            System.out.println("Hash verification successful!");
        } else {
            System.out.println("Hash verification falied :((((");
        }
    }

    public byte[] keyOne(Long masterKey) {
        byte[] keyOne = new byte[32];
        for (int i = 0; i < 32; i++) {
            if (i % 2 == 0)
                keyOne[i] = (byte) ((masterKey * 2) % 10);
            else
                keyOne[i] = (byte) ((masterKey++) % 10);
        }
        return keyOne;

    }

    public byte[] keyTwo(Long masterKey) {
        byte[] keyTwo = new byte[32];
        for (int i = 0; i < 32; i++) {
            if (i % 2 == 0)
                keyTwo[i] = (byte) ((masterKey++) % 10);
            else
                keyTwo[i] = (byte) ((masterKey * 2) % 10);
        }
        return keyTwo;
    }

    public byte[] keyThree(Long masterKey) {
        byte[] keyThree = new byte[32];
        for (int i = 0; i < 32; i++) {
            if (i % 3 == 0)
                keyThree[i] = (byte) ((masterKey++) % 10);
            else
                keyThree[i] = (byte) ((masterKey * 3) % 10);
        }
        return keyThree;
    }

    public byte[] keyFour(Long masterKey) {
        byte[] keyFour = new byte[32];
        for (int i = 0; i < 32; i++) {
            if (i % 3 == 0)
                keyFour[i] = (byte) ((masterKey * 3) % 10);
            else
                keyFour[i] = (byte) ((masterKey++) % 10);
        }
        return keyFour;
    }

    public String AESEncrypt(byte[] key, String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            // Encrypt the plain text
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("Encrypted AES text is: " + encryptedText);
            return encryptedText;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }

    }

    public String AESDecrypt(byte[] key, String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("Decrypted AES text is: " + decryptedText);
            return decryptedText;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String DESEncrypt(byte[] keyy, String plainText) {
        try {
            byte[] key = new byte[8];
            System.arraycopy(keyy, 0, key, 0, 7);

            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            // Encrypt the plain text
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("Encrypted DES text is: " + encryptedText);
            return encryptedText;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public String DESDecrypt(byte[] keyy, String encryptedText) {
        try {
            byte[] key = new byte[8];
            System.arraycopy(keyy, 0, key, 0, 7);
            // Decrypt the encrypted text
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "DES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("Decrypted DES text: " + decryptedText);
            return decryptedText;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public void checkIntegrity(byte[] message, byte[] key, byte[] mac, String alg) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey secretKey = new SecretKeySpec(key, alg);
        Mac macAlgorithm = Mac.getInstance(alg);
        macAlgorithm.init(secretKey);
        byte[] computedMac = macAlgorithm.doFinal(message);
        if(MessageDigest.isEqual(mac, computedMac))
        {
            System.out.println("Integrity of the data is verified!");
        }
    }
}
