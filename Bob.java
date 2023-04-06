import General.General;

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
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Bob {

    static final String idBob = new String("8019351793");

    public static void main(String args[]) {
        General general = new General();
        try {
            System.out.println("Bob has started.");

            // Creating a socket to connect with ALice
            ServerSocket serverSocket = new ServerSocket(1235);
            Socket serverAlice = serverSocket.accept();
            serverAlice.setSoTimeout(100000);
            System.out.println("Bob established connection with Alice!");

            Socket socketCA = new Socket("localhost", 1236);
            System.out.println("Alice established connection with CA");

            // Creating a bufferreader and printwriter to print to and read from socket
            // stream.
            BufferedReader br = new BufferedReader(new InputStreamReader(serverAlice.getInputStream()));
            PrintWriter pw = new PrintWriter(serverAlice.getOutputStream(), true);

            // Creating a bufferreader and printwriter to print to and read from the KDC
            // socket stream.
            PrintWriter pwCA = new PrintWriter(socketCA.getOutputStream(), true);
            BufferedReader brCA = new BufferedReader(new InputStreamReader(socketCA.getInputStream()));

            pwCA.println("Hey!");
            pwCA.println(idBob);

            //getting Bob's certificate from CA
            InputStream certStream = socketCA.getInputStream();
            byte[] certbytes = new byte[1024];
            FileOutputStream certout = new FileOutputStream("bob.crt");
            int bytesread = certStream.read(certbytes, 0, certbytes.length);
            certout.write(certbytes, 0, bytesread);

            System.out.println("Certificate received!");

            //receive Alice's certificate from Alice
            String str = br.readLine();
            if (str.equals("Hey!")) {
                InputStream inputCertStream = serverAlice.getInputStream();
                byte[] certBytes = new byte[1024];
                FileOutputStream certOut = new FileOutputStream("Compare/aliceRcd.crt");
                int bytesRead = inputCertStream.read(certBytes, 0, certBytes.length);
                certOut.write(certBytes, 0, bytesRead);
            }
            System.out.println("Received Alice's certificate!");

            //receive Alice's certificate from CA
            pwCA.println("NeedAlice!");
            InputStream certStrm = socketCA.getInputStream();
            byte[] certbytesOrg = new byte[1024];
            FileOutputStream crtout = new FileOutputStream("Compare/aliceOrg.crt");
            int bytesrd = certStrm.read(certbytesOrg, 0, certbytesOrg.length);
            crtout.write(certbytesOrg, 0, bytesrd);
            certStrm.close();

            System.out.println("Alice's certificate received from CA");

            //compare both certificates to check integrity of ALice
            FileInputStream file1 = new FileInputStream("Compare/aliceRcd.crt");
            FileInputStream file2 = new FileInputStream("Compare/aliceOrg.crt");
            byte[] file1Bytes = file1.readAllBytes();
            byte[] file2Bytes = file2.readAllBytes();
            boolean areFilesEqual = Arrays.equals(file1Bytes, file2Bytes);
            if (areFilesEqual) {
                System.out.println("Alice is verified!");
            } else {
                System.out.println("Alice could NOT be verified!");
            }
            file1.close();
            file2.close();

            //send Bob's certificate to Alice
            File aliceCert = new File("bob.crt");
            byte[] certbyts = Files.readAllBytes(aliceCert.toPath());
            OutputStream aliceCertOut = serverAlice.getOutputStream();
            aliceCertOut.write(certbyts);
            aliceCertOut.flush();

            KeyStore bobKS = KeyStore.getInstance("JKS");
            FileInputStream bobKSF = new FileInputStream("General/bob.jks");
            bobKS.load(bobKSF, "123456".toCharArray());

            // Get Bob's private key from the keystore
            PrivateKey bobPrivateKey = (PrivateKey) bobKS.getKey("bob", "123456".toCharArray());

            // Load Alice's public key certificate from alice.crt file
            CertificateFactory certFact = CertificateFactory.getInstance("X.509");
            FileInputStream aliceCF = new FileInputStream("alice.crt");
            Certificate aliceC = certFact.generateCertificate(aliceCF);
            java.security.PublicKey alicePublicKey = aliceC.getPublicKey();

            // setting up data input and output streams to communicate
            InputStream inputStream = serverAlice.getInputStream();
            DataInputStream dataInputStream = new DataInputStream(inputStream);
            OutputStream outputStream = serverAlice.getOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);

            // receive encrypted Ra from Alice
            int len1 = dataInputStream.readInt();
            byte[] encryptedRa = new byte[len1];
            dataInputStream.readFully(encryptedRa);

            //receive hash of Ra from Alice
            int len2 = dataInputStream.readInt();
            byte[] hashRa = new byte[len2];
            dataInputStream.readFully(hashRa);
            String decryptedRa = general.DecryptRSA(bobPrivateKey, encryptedRa);
            StringTokenizer stk = new StringTokenizer(decryptedRa, ";");
            String raStr = stk.nextToken();

            //verify hash
            general.verifyHash(general.getHash(decryptedRa), hashRa);

            // create, encrypt and send Rb
            long rbLong = general.giveRandom();
            str = Long.toString(rbLong);
            System.out.println("Message before encryption: " + str + ";SERVER");
            byte[] encryptedRb = general.EncryptRSA(alicePublicKey, str + ";SERVER");
            byte[] hashRb = general.getHash(str + ";SERVER");
            dataOutputStream.writeInt(encryptedRb.length);
            dataOutputStream.write(encryptedRb);
            dataOutputStream.writeInt(hashRb.length);
            dataOutputStream.write(hashRb);

            // generate master key
            Long masterKey = Long.parseLong(raStr) ^ rbLong;
            System.out.println("Master key is: " + Long.toString(masterKey));

            // generate 4 keys that are needed, the first two will be used for encryption
            // and the second two will be used for authentication
            byte[] key1 = general.keyOne(masterKey);
            byte[] key2 = general.keyTwo(masterKey);
            byte[] key3 = general.keyThree(masterKey);
            byte[] key4 = general.keyFour(masterKey);

            //Sample message communication with key1 and integrity check with key3
            String encryptedSample = br.readLine();
            String hashSample = br.readLine();
            String macS = br.readLine();
            String decryptedSample = general.DESDecrypt(key1, encryptedSample);
            if (hashSample.equals(new String(general.getHash(decryptedSample)))) {
                System.out.println("Hash verified for sample message from client to server!");
            }
            SecretKey secretKeyI = new SecretKeySpec(key3, "HmacSHA256");
            Mac macAlg = Mac.getInstance("HmacSHA256");
            macAlg.init(secretKeyI);
            String computedMac = new String(macAlg.doFinal(decryptedSample.getBytes()));
            if(computedMac.equals(macS))
            {
                System.out.println("Integrity verified for the sample from client to server message!");
            }
            else
            {
                System.out.println("Integrity verification FAILED for the sample message from client to server!"); 
            }

            //sample to show integrity failure
            encryptedSample = br.readLine();
            hashSample = br.readLine();
            macS = br.readLine();
            decryptedSample = general.DESDecrypt(key1, encryptedSample);
            if (hashSample.equals(new String(general.getHash(decryptedSample)))) {
                System.out.println("Hash verified for sample message from client to server!");
            }
            secretKeyI = new SecretKeySpec(key3, "HmacSHA256");
            macAlg = Mac.getInstance("HmacSHA256");
            macAlg.init(secretKeyI);
            computedMac = new String(macAlg.doFinal(decryptedSample.getBytes()));
            if(computedMac.equals(macS))
            {
                System.out.println("Integrity verified for the sample from client to server message!");
            }
            else
            {
                System.out.println("Integrity verification FAILED for the sample message from client to server!"); 
            }

            //file transfer with key2 and key4
            String choice = br.readLine();

            if (choice.equals("1")) {

                SecretKeySpec keySpec = new SecretKeySpec(key2, "AES");
                SecretKey secretKey = keySpec;
                byte[] iv = new byte[16];
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);

                // Encrypt the file using AES
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                Path filePath = Paths.get("General/smiley.jpg");
                byte[] encryptedBytes = cipher.doFinal(Files.readAllBytes(filePath));
                byte[] originalbytedata = Files.readAllBytes(filePath);
                String strtemp = new String(originalbytedata) + ";SERVER";
                byte[] hashtemp = general.getHash(strtemp);

                SecretKey secretKeyIntegrity = new SecretKeySpec(key4, "HmacSHA256");
                Mac macAlgorithm = Mac.getInstance("HmacSHA256");
                macAlgorithm.init(secretKeyIntegrity);
                byte[] mac = macAlgorithm.doFinal(originalbytedata);

                // Send the encrypted file, IV, and AES key to the client
                DataOutputStream dos = new DataOutputStream(serverAlice.getOutputStream());
                dos.writeInt(hashtemp.length);
                dos.write(hashtemp);
                dos.writeInt(encryptedBytes.length);
                dos.write(encryptedBytes);
                byte[] keyBytes = secretKey.getEncoded();
                dos.writeInt(keyBytes.length);
                dos.write(keyBytes);
                dos.writeInt(iv.length);
                dos.write(iv);
                dos.writeInt(mac.length);
                dos.write(mac);

                dos.flush();

            }

            else if (choice.equals("2")) {
                byte[] key = new byte[8];
                System.arraycopy(key2, 0, key, 0, 7);
                SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
                SecretKey secretKey = keySpec;
                byte[] iv = new byte[8];
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);

                // Encrypt the file using DES
                Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                Path filePath = Paths.get("General/smiley.jpg");
                byte[] encryptedBytes = cipher.doFinal(Files.readAllBytes(filePath));

                byte[] originalbytedata = Files.readAllBytes(filePath);
                String strtemp = new String(originalbytedata) + ";SERVER";
                byte[] hashtemp = general.getHash(strtemp);

                SecretKey secretKeyIntegrity = new SecretKeySpec(key4, "HmacSHA256");
                Mac macAlgorithm = Mac.getInstance("HmacSHA256");
                macAlgorithm.init(secretKeyIntegrity);
                byte[] mac = macAlgorithm.doFinal(originalbytedata);

                // Send the encrypted file, IV, and DES key to the client
                DataOutputStream dos = new DataOutputStream(serverAlice.getOutputStream());
                dos.writeInt(hashtemp.length);
                dos.write(hashtemp);
                dos.writeInt(encryptedBytes.length);
                dos.write(encryptedBytes);
                byte[] keyBytes = secretKey.getEncoded();
                dos.writeInt(keyBytes.length);
                dos.write(keyBytes);
                dos.writeInt(iv.length);
                dos.write(iv);
                dos.writeInt(mac.length);
                dos.write(mac);

                dos.flush();

            }

        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
