import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;

public class CA {
    static final String idALice = new String("8018142327");
    static final String idBob = new String("8019351793");

    public static void main(String args[]) {
        try {
            System.out.println("CA has started.");

            // Creating a socket to connect with Alice and Bob
            ServerSocket serverSocket = new ServerSocket(1234);
            Socket server = serverSocket.accept();
            server.setSoTimeout(100000);
            System.out.println("Connection established with Alice!");

            ServerSocket serverSocketBob = new ServerSocket(1236);
            Socket serverBob = serverSocketBob.accept();
            serverBob.setSoTimeout(100000);
            System.out.println("Connection established with Bob!");

            // Creating a bufferreader and printwriter to print to and read from socket
            // stream.
            BufferedReader brAl = new BufferedReader(new InputStreamReader(server.getInputStream()));
            PrintWriter pwAl = new PrintWriter(server.getOutputStream(), true);

            BufferedReader brB = new BufferedReader(new InputStreamReader(serverBob.getInputStream()));
            PrintWriter pwB = new PrintWriter(serverBob.getOutputStream(), true);

            //send certificate to Alice
            String str = brAl.readLine();
            if (str.equals("Hey!")) {
                str = brAl.readLine();
                if (str.equals(idALice)) {
                    File aliceCert = new File("General/alice.crt");
                    byte[] certBytes = Files.readAllBytes(aliceCert.toPath());
                    // send the file to the client
                    OutputStream aliceCertOut = server.getOutputStream();
                    aliceCertOut.write(certBytes);
                    aliceCertOut.flush();
                    System.out.println("Sent certificate to Alice");
                }
            }

            //send certificate to Bob
            str = brB.readLine();
            if (str.equals("Hey!")) {
                str = brB.readLine();
                if (str.equals(idBob)) {
                    File bobCert = new File("General/bob.crt");
                    byte[] certBytes = Files.readAllBytes(bobCert.toPath());
                    // send the file to the client
                    OutputStream bobCertOut = serverBob.getOutputStream();
                    bobCertOut.write(certBytes);
                    System.out.println("Sent certificate to Bob");
                }
            }

            //send Alice's certificate to Bob
            str = brB.readLine();
            if (str.equals("NeedAlice!")) {
                File bobCrt = new File("General/alice.crt");
                byte[] certByte = Files.readAllBytes(bobCrt.toPath());
                // send the file to the client
                OutputStream bobCrtOut = serverBob.getOutputStream();
                bobCrtOut.write(certByte);
                bobCrtOut.flush();
                System.out.println("Sent Alice's certificate to Bob");
            }

            //send Bob's certificate to Alice
            str = brAl.readLine();
            if (str.equals("NeedBob!")) {
                File bobCrt = new File("General/bob.crt");
                byte[] certByte = Files.readAllBytes(bobCrt.toPath());
                // send the file to the client
                OutputStream bobCrtOut = server.getOutputStream();
                bobCrtOut.write(certByte);
                bobCrtOut.flush();
                // close the socket and server
                bobCrtOut.close();
                System.out.println("Sent Bob's certificate to Alice");
            }

        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
