import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient {
    private static final int BUFFER_SIZE = 1024;
    private static final String SIGNUP_CMD = "SIGNUP:";
    private static final String SIGNIN_CMD = "SIGNIN:";
    private static final String MESSAGE_CMD = "MESSAGE ";
    private static final String GREETING_CMD = "GREETING";
    private static final String SECURE_SIGNUP_CMD = "SECURE_SIGNUP:";
    private static final String SECURE_SIGNIN_CMD = "SECURE_SIGNIN:";
    private static final String SECURE_MESSAGE_CMD = "SECURE_MESSAGE:";
    private static final String BROADCAST_CMD = "BROADCAST:";
    private static final String SIGNUP_OK = "SIGNUP_OK";
    private static final String SIGNIN_OK = "SIGNIN_OK";
    private static final String SIGNUP_FAIL = "SIGNUP_FAIL:";
    private static final String SIGNIN_FAIL = "SIGNIN_FAIL:";
    private static final byte[] SESSION_KEY = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final int serverPort;
    private boolean authenticated = false;
    private final Scanner scanner = new Scanner(System.in);
    private SecretKey sessionKey;
    private String username;

    public ChatClient(String serverIp, int serverPort) throws IOException {
        this.serverAddress = InetAddress.getByName(serverIp);
        this.serverPort = serverPort;
        this.socket = new DatagramSocket();
        this.sessionKey = new SecretKeySpec(SESSION_KEY, "AES");
    }

    public void start() throws IOException {
        authenticate();
        if (!authenticated) {
            System.out.println("Authentication failed. Exiting.");
            return;
        }

        send(GREETING_CMD);

        Thread receiver = new Thread(this::receiveMessages);
        receiver.start();

        System.out.print("Enter message (or 'exit' to quit, use '@username message' for direct, 'broadcast message' for broadcast): \n");
        while (true) {
            System.out.print("] ");
            if (!scanner.hasNextLine()) {
                break;
            }
            String line = scanner.nextLine();
            if (line.equalsIgnoreCase("exit")) {
                break;
            }
            if (line.startsWith("broadcast ")) {
                sendBroadcast(line.substring("broadcast ".length()));
            } else if (line.startsWith("@")) {
                int spaceIndex = line.indexOf(" ");
                if (spaceIndex != -1) {
                    String recipient = line.substring(1, spaceIndex);
                    String message = line.substring(spaceIndex + 1);
                    sendDirectMessage(recipient, message);
                }
            } else {
                sendMessage(line);
            }
        }

        socket.close();
        System.out.println("Client exited.");
    }

    private void authenticate() throws IOException {
        while (true) {
            System.out.print("Do you want to sign up or sign in? (signup/signin): ");
            String choice = scanner.nextLine().trim();
            System.out.print("Enter username: ");
            username = scanner.nextLine().trim();
            String password;

            Console console = System.console();
            if (console != null) {
                char[] passwordChars = console.readPassword("Enter password: ");
                password = new String(passwordChars);
            } else {
                System.out.print("Enter password (visible): ");
                password = scanner.nextLine().trim();
            }

            String msg;
            if (choice.equalsIgnoreCase("signup")) {
                String credentials = username + ":" + password;
                String encrypted = encrypt(credentials, sessionKey);
                msg = SECURE_SIGNUP_CMD + encrypted;
            } else if (choice.equalsIgnoreCase("signin")) {
                String credentials = username + ":" + password;
                String encrypted = encrypt(credentials, sessionKey);
                msg = SECURE_SIGNIN_CMD + encrypted;
            } else {
                System.out.println("Invalid choice.");
                continue;
            }

            send(msg);

            byte[] buffer = new byte[BUFFER_SIZE];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);
            String response = new String(packet.getData(), 0, packet.getLength());

            if (response.startsWith(SIGNUP_OK) || response.startsWith(SIGNIN_OK)) {
                System.out.println("Authentication successful.");
                authenticated = true;
                break;
            } else {
                System.out.println("Authentication failed: " + response);
            }
        }
    }

    private void sendMessage(String msg) throws IOException {
        String message = MESSAGE_CMD + msg;
        send(message);
    }

    private void sendDirectMessage(String recipient, String msg) throws IOException {
        String message = recipient + ":" + msg;
        String encrypted = encrypt(message, sessionKey);
        send(SECURE_MESSAGE_CMD + encrypted);
    }

    private void sendBroadcast(String msg) throws IOException {
        String encrypted = encrypt(msg, sessionKey);
        send(BROADCAST_CMD + encrypted);
    }

    private void receiveMessages() {
        byte[] buffer = new byte[BUFFER_SIZE];
        while (true) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                String received = new String(packet.getData(), 0, packet.getLength());
                if (received.startsWith(SECURE_MESSAGE_CMD)) {
                    String encrypted = received.substring(SECURE_MESSAGE_CMD.length());
                    String decrypted = decrypt(encrypted, sessionKey);
                    System.out.print("\r" + decrypted + "\n] ");
                } else if (received.startsWith(BROADCAST_CMD)) {
                    String encrypted = received.substring(BROADCAST_CMD.length());
                    String decrypted = decrypt(encrypted, sessionKey);
                    System.out.print("\r" + decrypted + "\n] ");
                } else {
                    System.out.print("\r" + received + "\n] ");
                }
                System.out.flush();
            } catch (IOException e) {
                break;
            }
        }
    }

    private String encrypt(String data, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    private String decrypt(String encryptedData, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decrypted);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    private void send(String msg) throws IOException {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, serverAddress, serverPort);
        socket.send(packet);
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java ChatClient <server-ip> <port>");
            return;
        }

        try {
            ChatClient client = new ChatClient(args[0], Integer.parseInt(args[1]));
            client.start();
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}