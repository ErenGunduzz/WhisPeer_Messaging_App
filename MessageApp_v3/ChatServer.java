import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ChatServer {
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

    private static final Map<String, String> authenticatedClients = new HashMap<>();
    private static final Map<String, SecretKey> clientKeys = new HashMap<>();
    private static Connection db;
    private static final String LOG_FILE = "server.log";
    private static final byte[] SESSION_KEY = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: java ChatServer <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        initDatabase();

        DatagramSocket socket = new DatagramSocket(port);
        byte[] buffer = new byte[BUFFER_SIZE];
        log("Server listening on port " + port);

        while (true) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);
            String msg = new String(packet.getData(), 0, packet.getLength());
            InetAddress address = packet.getAddress();
            int clientPort = packet.getPort();
            String clientKey = address.getHostAddress() + ":" + clientPort;

            if (msg.startsWith(SIGNUP_CMD)) {
                String[] parts = msg.substring(SIGNUP_CMD.length()).split(":", 2);
                if (parts.length < 2) continue;
                String username = parts[0];
                String password = parts[1];
                if (userExists(username)) {
                    send(socket, SIGNUP_FAIL + "Username already exists", address, clientPort);
                    log("SIGNUP FAIL (exists): " + username);
                } else {
                    String salt = generateSalt();
                    String hash = hashPassword(password, salt);
                    insertUser(username, salt, hash);
                    authenticatedClients.put(clientKey, username);
                    clientKeys.put(clientKey, new SecretKeySpec(SESSION_KEY, "AES"));
                    send(socket, SIGNUP_OK, address, clientPort);
                    log("User signed up: " + username + " from " + clientKey);
                }
            } else if (msg.startsWith(SIGNIN_CMD)) {
                String[] parts = msg.substring(SIGNIN_CMD.length()).split(":", 2);
                if (parts.length < 2) continue;
                String username = parts[0];
                String password = parts[1];
                String[] result = getUser(username);
                if (result != null) {
                    String salt = result[0];
                    String storedHash = result[1];
                    String inputHash = hashPassword(password, salt);
                    if (storedHash.equals(inputHash)) {
                        authenticatedClients.put(clientKey, username);
                        clientKeys.put(clientKey, new SecretKeySpec(SESSION_KEY, "AES"));
                        send(socket, SIGNIN_OK, address, clientPort);
                        log("User signed in: " + username + " from " + clientKey);
                    } else {
                        send(socket, SIGNIN_FAIL + "Invalid credentials", address, clientPort);
                        log("SIGNIN FAIL (wrong password): " + username);
                    }
                } else {
                    send(socket, SIGNIN_FAIL + "User not found", address, clientPort);
                    log("SIGNIN FAIL (no such user): " + username);
                }
            } else if (msg.startsWith(SECURE_SIGNUP_CMD)) {
                String encrypted = msg.substring(SECURE_SIGNUP_CMD.length());
                String decrypted = decrypt(encrypted, new SecretKeySpec(SESSION_KEY, "AES"));
                String[] parts = decrypted.split(":", 2);
                if (parts.length < 2) continue;
                String username = parts[0];
                String password = parts[1];
                if (userExists(username)) {
                    send(socket, SIGNUP_FAIL + "Username already exists", address, clientPort);
                    log("SECURE_SIGNUP FAIL (exists): " + username);
                } else {
                    String salt = generateSalt();
                    String hash = hashPassword(password, salt);
                    insertUser(username, salt, hash);
                    authenticatedClients.put(clientKey, username);
                    clientKeys.put(clientKey, new SecretKeySpec(SESSION_KEY, "AES"));
                    send(socket, SIGNUP_OK, address, clientPort);
                    log("User signed up securely: " + username + " from " + clientKey);
                }
            } else if (msg.startsWith(SECURE_SIGNIN_CMD)) {
                String encrypted = msg.substring(SECURE_SIGNIN_CMD.length());
                String decrypted = decrypt(encrypted, new SecretKeySpec(SESSION_KEY, "AES"));
                String[] parts = decrypted.split(":", 2);
                if (parts.length < 2) continue;
                String username = parts[0];
                String password = parts[1];
                String[] result = getUser(username);
                if (result != null) {
                    String salt = result[0];
                    String storedHash = result[1];
                    String inputHash = hashPassword(password, salt);
                    if (storedHash.equals(inputHash)) {
                        authenticatedClients.put(clientKey, username);
                        clientKeys.put(clientKey, new SecretKeySpec(SESSION_KEY, "AES"));
                        send(socket, SIGNIN_OK, address, clientPort);
                        log("User signed in securely: " + username + " from " + clientKey);
                    } else {
                        send(socket, SIGNIN_FAIL + "Invalid credentials", address, clientPort);
                        log("SECURE_SIGNIN FAIL (wrong password): " + username);
                    }
                } else {
                    send(socket, SIGNIN_FAIL + "User not found", address, clientPort);
                    log("SECURE_SIGNIN FAIL (no such user): " + username);
                }
            } else if (msg.startsWith(SECURE_MESSAGE_CMD)) {
                if (!authenticatedClients.containsKey(clientKey)) continue;
                String encrypted = msg.substring(SECURE_MESSAGE_CMD.length());
                String decrypted = decrypt(encrypted, clientKeys.get(clientKey));
                String[] parts = decrypted.split(":", 2);
                if (parts.length < 2) continue;
                String recipient = parts[0];
                String content = parts[1];
                String sender = authenticatedClients.get(clientKey);
                String outMsg = "<from " + sender + "> " + content;
                for (String key : authenticatedClients.keySet()) {
                    if (authenticatedClients.get(key).equals(recipient)) {
                        String[] ipPort = key.split(":");
                        InetAddress targetIP = InetAddress.getByName(ipPort[0]);
                        int targetPort = Integer.parseInt(ipPort[1]);
                        String encryptedOut = encrypt(outMsg, clientKeys.get(key));
                        send(socket, SECURE_MESSAGE_CMD + encryptedOut, targetIP, targetPort);
                        log("Direct message from " + sender + " to " + recipient + ": " + content);
                        break;
                    }
                }
            } else if (msg.startsWith(BROADCAST_CMD)) {
                if (!authenticatedClients.containsKey(clientKey)) continue;
                String encrypted = msg.substring(BROADCAST_CMD.length());
                String decrypted = decrypt(encrypted, clientKeys.get(clientKey));
                String sender = authenticatedClients.get(clientKey);
                String outMsg = "<from " + sender + "> " + decrypted;
                for (String key : authenticatedClients.keySet()) {
                    String[] ipPort = key.split(":");
                    InetAddress targetIP = InetAddress.getByName(ipPort[0]);
                    int targetPort = Integer.parseInt(ipPort[1]);
                    String encryptedOut = encrypt(outMsg, clientKeys.get(key));
                    send(socket, BROADCAST_CMD + encryptedOut, targetIP, targetPort);
                }
                log("Secure broadcast from " + sender + ": " + decrypted);
            } else if (msg.startsWith(MESSAGE_CMD)) {
                if (!authenticatedClients.containsKey(clientKey)) continue;
                String content = msg.substring(MESSAGE_CMD.length());
                String sender = authenticatedClients.get(clientKey);
                String outMsg = "<from " + sender + "> " + content;
                for (String key : authenticatedClients.keySet()) {
                    String[] ipPort = key.split(":");
                    InetAddress targetIP = InetAddress.getByName(ipPort[0]);
                    int targetPort = Integer.parseInt(ipPort[1]);
                    send(socket, outMsg, targetIP, targetPort);
                }
                log("Broadcast from " + sender + ": " + content);
            } else if (msg.equals(GREETING_CMD)) {
                if (authenticatedClients.containsKey(clientKey)) {
                    String user = authenticatedClients.get(clientKey);
                    log("GREETING from " + user);
                }
            }
        }
    }

    private static void initDatabase() throws SQLException {
        db = DriverManager.getConnection("jdbc:sqlite:users.db");
        try (Statement stmt = db.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT, hash TEXT)");
        }
    }

    private static boolean userExists(String username) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("SELECT 1 FROM users WHERE username = ?")) {
            stmt.setString(1, username);
            return stmt.executeQuery().next();
        }
    }

    private static void insertUser(String username, String salt, String hash) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("INSERT INTO users (username, salt, hash) VALUES (?, ?, ?);")) {
            stmt.setString(1, username);
            stmt.setString(2, salt);
            stmt.setString(3, hash);
            stmt.executeUpdate();
        }
    }

    private static String[] getUser(String username) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("SELECT salt, hash FROM users WHERE username = ?")) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new String[]{rs.getString("salt"), rs.getString("hash")};
            }
        }
        return null;
    }

    private static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static String hashPassword(String password, String salt) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(salt), 100000, 256);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Hashing failed", e);
        }
    }

    private static String encrypt(String data, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    private static String decrypt(String encryptedData, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decrypted);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    private static void send(DatagramSocket socket, String msg, InetAddress addr, int port) throws IOException {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr, port);
        socket.send(packet);
    }

    private static void log(String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String logEntry = "[" + timestamp + "] " + message;
        System.out.println(logEntry);
        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(logEntry);
        } catch (IOException e) {
            System.err.println("Failed to write to log file: " + e.getMessage());
        }
    }
}