import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Scanner;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import General.General;

public class Alice {
    static final String idALice = new String("8018142327");

    public static void main(String args[]) {
        try {

            System.out.println("Alice has started.");
            General general = new General();
            // Creating a socket to connect with Bob and CA
            Socket socket = new Socket("localhost", 1235);
            socket.setSoTimeout(100000);
            System.out.println("Alice established connection with Bob");
            Socket socketCA = new Socket("localhost", 1234);
            System.out.println("Alice established connection with CA");

            // Creating a bufferreader and printwriter to print to and read from socket
            // stream.
            PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Creating a bufferreader and printwriter to print to and read from the KDC
            // socket stream.
            PrintWriter pwCA = new PrintWriter(socketCA.getOutputStream(), true);
            BufferedReader brCA = new BufferedReader(new InputStreamReader(socketCA.getInputStream()));

            // ask CA for Alice's certificate
            pwCA.println("Hey!");
            pwCA.println(idALice);
            InputStream inputCertStream = socketCA.getInputStream();
            byte[] certBytes = new byte[1024];
            FileOutputStream certOut = new FileOutputStream("alice.crt");
            int bytesRead = inputCertStream.read(certBytes, 0, certBytes.length);
            certOut.write(certBytes, 0, bytesRead);
            System.out.println("Alice's certificate received!");

            // send Alice's certificate to Bob
            pw.println("Hey!");
            File aliceCert = new File("alice.crt");
            byte[] certbytes = Files.readAllBytes(aliceCert.toPath());
            // send the file to the client
            OutputStream aliceCertOut = socket.getOutputStream();
            aliceCertOut.write(certbytes);
            aliceCertOut.flush();

            // receive Bob's certificate from Bob
            InputStream certStrm = socket.getInputStream();
            byte[] certbytesOrg = new byte[1024];
            FileOutputStream crtout = new FileOutputStream("Compare/bobRcd.crt");
            int bytesrd = certStrm.read(certbytesOrg, 0, certbytesOrg.length);
            crtout.write(certbytesOrg, 0, bytesrd);

            System.out.println("Bob's certificate received from Bob");

            // receive Bob's certificate from CA
            pwCA.println("NeedBob!");
            InputStream certSm = socketCA.getInputStream();
            byte[] certbytOrg = new byte[1024];
            FileOutputStream cert_Out = new FileOutputStream("Compare/bobOrg.crt");
            int bytes_rd = certSm.read(certbytOrg, 0, certbytOrg.length);
            cert_Out.write(certbytOrg, 0, bytes_rd);

            System.out.println("Bob's certificate received from CA");
            // compare both certificates of Bob to check the integrity of Bob's certificate
            FileInputStream file1 = new FileInputStream("Compare/bobRcd.crt");
            FileInputStream file2 = new FileInputStream("Compare/bobOrg.crt");
            byte[] file1Bytes = file1.readAllBytes();
            byte[] file2Bytes = file2.readAllBytes();
            boolean areFilesEqual = Arrays.equals(file1Bytes, file2Bytes);
            if (areFilesEqual) {
                System.out.println("Bob is verified!");
            } else {
                System.out.println("Bob could NOT be verified!");
            }
            file1.close();
            file2.close();

            KeyStore aliceKS = KeyStore.getInstance("JKS");
            FileInputStream aliceKSF = new FileInputStream("General/alice.jks");
            aliceKS.load(aliceKSF, "123456".toCharArray());

            // Get Alice's private key from the keystore
            PrivateKey alicePrivateKey = (PrivateKey) aliceKS.getKey("alice", "123456".toCharArray());

            // Load Bob's public key certificate from bob.crt file
            CertificateFactory certFact = CertificateFactory.getInstance("X.509");
            FileInputStream bobCF = new FileInputStream("bob.crt");
            Certificate bobC = certFact.generateCertificate(bobCF);
            java.security.PublicKey bobPublicKey = bobC.getPublicKey();

            // create, encrypt and send Ra
            long raLong = general.giveRandom();
            String str = Long.toString(raLong);
            System.out.println("Message before encryption: " + str + ";CLIENT");
            byte[] encryptedRa = general.EncryptRSA(bobPublicKey, str + ";CLIENT");
            byte[] hashRa = general.getHash(str + ";CLIENT");

            // setting up data input and output streams to communicate
            OutputStream outputStream = socket.getOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
            InputStream inputStream = socket.getInputStream();
            DataInputStream dataInputStream = new DataInputStream(inputStream);
            dataOutputStream.writeInt(encryptedRa.length);
            dataOutputStream.write(encryptedRa);

            dataOutputStream.writeInt(hashRa.length);
            dataOutputStream.write(hashRa);

            // receive encrypted Rb, Rb's hash from Bob and decrypt Rb
            int len1 = dataInputStream.readInt();
            byte[] encryptedRb = new byte[len1];
            dataInputStream.readFully(encryptedRb);
            int len2 = dataInputStream.readInt();
            byte[] hashRb = new byte[len2];
            dataInputStream.readFully(hashRb);
            String decryptedRb = general.DecryptRSA(alicePrivateKey, encryptedRb);
            StringTokenizer stk = new StringTokenizer(decryptedRb, ";");
            String rbStr = stk.nextToken();

            general.verifyHash(general.getHash(decryptedRb), hashRb);

            // generate master key
            Long masterKey = Long.parseLong(rbStr) ^ raLong;
            System.out.println("Master key is: " + Long.toString(masterKey));

            // generate 4 keys that are needed, the first two will be used for encryption
            // and the second two will be used for authentication
            byte[] key1 = general.keyOne(masterKey);
            byte[] key2 = general.keyTwo(masterKey);
            byte[] key3 = general.keyThree(masterKey);
            byte[] key4 = general.keyFour(masterKey);

            // send a sample message to server using key1 and integrity check with key3
            str = "This is a sample message being sent from Client to Server using Key1!;CLIENT";
            String hashSample = new String(general.getHash(str));
            String encryptedSample = general.DESEncrypt(key1, str);
            String encryptedSampleERRORRED = general.DESEncrypt(key1, str+" ");
            SecretKey secretKeyI = new SecretKeySpec(key3, "HmacSHA256");
            Mac macAlg = Mac.getInstance("HmacSHA256");
            macAlg.init(secretKeyI);
            String macS = new String(macAlg.doFinal(str.getBytes()));
            pw.println(encryptedSample);
            pw.println(hashSample);
            pw.println(macS);

            //sample message to show integrity failure
            pw.println(encryptedSampleERRORRED);
            pw.println(hashSample);
            pw.println(macS);

            // send file securely using key2 and integrity check with key4
            System.out.println();
            System.out.println("Choose either 1 or 2 algorithm for secure file transfer: ");
            System.out.println("1. AES");
            System.out.println("2. DES");

            Scanner scanner = new Scanner(System.in);
            int choice = scanner.nextInt();

            switch (choice) {
                case 1: {
                    // execute AES
                    pw.println("1");

                    System.out.println("You chose to use AES!\n");
                    DataInputStream dis = new DataInputStream(socket.getInputStream());
                    int hashSize = dis.readInt();
                    byte[] hashbytes = new byte[hashSize];
                    dis.readFully(hashbytes);
                    int fileSize = dis.readInt();
                    byte[] encryptedBytes = new byte[fileSize];
                    dis.readFully(encryptedBytes);
                    int keySize = dis.readInt();
                    byte[] keyBytes = new byte[keySize];
                    dis.readFully(keyBytes);
                    int ivSize = dis.readInt();
                    byte[] ivBytes = new byte[ivSize];
                    dis.readFully(ivBytes);
                    int macSize = dis.readInt();
                    byte[] mac = new byte[macSize];
                    dis.readFully(mac);

                    // Decrypt the file using AES
                    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
                    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

                    String strtemp = new String(decryptedBytes) + ";SERVER";
                    byte[] hashtemp = general.getHash(strtemp);
                    general.verifyHash(hashbytes, hashtemp);

                    // Save the decrypted file to disk
                    Path filePath = Paths.get("rcd.jpg");
                    Files.write(filePath, decryptedBytes);

                    SecretKey secretKeyIntegrity = new SecretKeySpec(key4, "HmacSHA256");
                    Mac macAlgorithm = Mac.getInstance("HmacSHA256");
                    macAlgorithm.init(secretKeyIntegrity);
                    byte[] macComputed = macAlgorithm.doFinal(decryptedBytes);

                    // verify the integrity of the content
                    if (Arrays.equals(mac, macComputed)) {
                        System.out.println("Integrity of the content is VERIFIED!");
                    } else {
                        System.out.println("Integrity check FAILED!");
                    }

                    break;
                }
                case 2: {
                    pw.println("2");
                    System.out.println("You chose to use DES!\n");

                    DataInputStream dis = new DataInputStream(socket.getInputStream());
                    int hashSize = dis.readInt();
                    byte[] hashbytes = new byte[hashSize];
                    dis.readFully(hashbytes);
                    int fileSize = dis.readInt();
                    byte[] encryptedBytes = new byte[fileSize];
                    dis.readFully(encryptedBytes);
                    int keySize = dis.readInt();
                    byte[] keyBytes = new byte[keySize];
                    dis.readFully(keyBytes);
                    int ivSize = dis.readInt();
                    byte[] ivBytes = new byte[ivSize];
                    dis.readFully(ivBytes);
                    int macSize = dis.readInt();
                    byte[] mac = new byte[macSize];
                    dis.readFully(mac);

                    // Decrypt the file using AES
                    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "DES");
                    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
                    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
                    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

                    String strtemp = new String(decryptedBytes) + ";SERVER";
                    byte[] hashtemp = general.getHash(strtemp);
                    general.verifyHash(hashbytes, hashtemp);
                    // Save the decrypted file to disk
                    Path filePath = Paths.get("rcd.jpg");
                    Files.write(filePath, decryptedBytes);

                    SecretKey secretKeyIntegrity = new SecretKeySpec(key4, "HmacSHA256");
                    Mac macAlgorithm = Mac.getInstance("HmacSHA256");
                    macAlgorithm.init(secretKeyIntegrity);
                    byte[] macComputed = macAlgorithm.doFinal(decryptedBytes);

                    // verify the integrity of the content
                    if (Arrays.equals(mac, macComputed)) {
                        System.out.println("Integrity of the content is VERIFIED!");
                    } else {
                        System.out.println("Integrity check FAILED!");
                    }

                    break;
                }

                default:
                    System.out.println("Try again by choosing either 1 or 2.");
                    break;
            }

            // check for file differences after the secure file transfer
            FileInputStream org = new FileInputStream("General/smiley.jpg");
            FileInputStream rcd = new FileInputStream("rcd.jpg");
            byte[] orgBytes = org.readAllBytes();
            byte[] rcdBytes = rcd.readAllBytes();
            boolean areEqual = Arrays.equals(orgBytes, rcdBytes);
            if (areEqual) {
                System.out.println("No differences found in the original and the received file.");
                System.out.println("SUCCESS!");
            } else {
                System.out.println("There are differences in the files! Your code failed!");
            }
            org.close();
            rcd.close();

        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
