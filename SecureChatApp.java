import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;

/**
 * SecureChatApp — RSA Encrypted Multi-Client Chat
 * 
 * Usage:
 *  1️⃣ Compile: javac SecureChatApp.java
 *  2️⃣ Start server: java SecureChatApp
 *  3️⃣ Start client: java SecureChatApp client
 *
 * Uses 1024-bit RSA encryption on port 3000.
 * Note: RSA supports only short messages (≈100 chars).
 */
public class SecureChatApp {

    private static final int PORT = 3000;
    private static final String HOST = "127.0.0.1";
    private static final int KEY_SIZE = 1024;
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    // ==============================================================
    // 🔐 RSA Utility Class
    // ==============================================================
    private static class RSA {
        public static KeyPair generateKeyPair() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEY_SIZE);
            return keyGen.generateKeyPair();
        }

        public static String encrypt(String text, PublicKey key) throws Exception {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encrypted);
        }

        public static String decrypt(String base64Cipher, PrivateKey key) throws Exception {
            byte[] cipherBytes = Base64.getDecoder().decode(base64Cipher);
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(cipherBytes);
            return new String(decrypted, "UTF-8");
        }

        public static String publicKeyToBase64(PublicKey key) {
            return Base64.getEncoder().encodeToString(key.getEncoded());
        }

        public static PublicKey base64ToPublicKey(String base64Key) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        }
    }

    // ==============================================================
    // 🖥️ Chat Server
    // ==============================================================
    private static class ChatServer {

        private static final ConcurrentHashMap<String, ClientHandler> connectedClients = new ConcurrentHashMap<>();
        private static KeyPair serverKeys;

        private static class ClientHandler implements Runnable {
            private final Socket socket;
            private BufferedReader in;
            private PrintWriter out;
            private PublicKey clientPublicKey;
            private String nickname;

            public ClientHandler(Socket socket) throws IOException {
                this.socket = socket;
                this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                this.out = new PrintWriter(socket.getOutputStream(), true);
            }

            private void sendEncrypted(String message) {
                try {
                    String encrypted = RSA.encrypt(message, clientPublicKey);
                    out.println(encrypted);
                } catch (Exception e) {
                    System.err.println("[Server Error] Failed to send to " + nickname + ": " + e.getMessage());
                }
            }

            @Override
            public void run() {
                try {
                    // Step 1: Key exchange
                    out.println(RSA.publicKeyToBase64(serverKeys.getPublic())); // send server key
                    clientPublicKey = RSA.base64ToPublicKey(in.readLine()); // receive client key

                    // Step 2: Get nickname
                    nickname = RSA.decrypt(in.readLine(), serverKeys.getPrivate());
                    if (nickname == null || nickname.isBlank() || connectedClients.containsKey(nickname)) {
                        sendEncrypted("[Server] Invalid or duplicate nickname. Disconnecting...");
                        return;
                    }

                    // Step 3: Register client
                    connectedClients.put(nickname, this);
                    System.out.println("[Server] " + nickname + " joined from " + socket.getInetAddress());
                    broadcast("[Server] " + nickname + " joined the chat!");

                    // Step 4: Listen for messages
                    String incoming;
                    while ((incoming = in.readLine()) != null) {
                        if (incoming.isEmpty()) continue;
                        String message = RSA.decrypt(incoming, serverKeys.getPrivate());
                        broadcast("[" + nickname + "]: " + message);
                    }

                } catch (SocketException e) {
                    // Client disconnected
                } catch (Exception e) {
                    System.err.println("[Server Error] " + e.getMessage());
                } finally {
                    if (nickname != null) {
                        connectedClients.remove(nickname);
                        System.out.println("[Server] " + nickname + " disconnected.");
                        broadcast("[Server] " + nickname + " left the chat.");
                    }
                    try { socket.close(); } catch (IOException ignored) {}
                }
            }
        }

        private static void broadcast(String message) {
            for (ClientHandler client : connectedClients.values()) {
                client.sendEncrypted(message);
            }
        }

        public static void start() {
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                serverKeys = RSA.generateKeyPair();
                System.out.println("[Server] Ready and listening on port " + PORT + "...");
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    new Thread(new ClientHandler(clientSocket)).start();
                }
            } catch (Exception e) {
                System.err.println("[Server Fatal Error] " + e.getMessage());
            }
        }
    }

    // ==============================================================
    // 💻 Chat Client
    // ==============================================================
    private static class ChatClient {
        public static void start() {
            Scanner scanner = new Scanner(System.in);
            System.out.print("[Setup] Enter your nickname: ");
            String nickname = scanner.nextLine().trim();

            try (Socket socket = new Socket(HOST, PORT)) {
                System.out.println("[Client] Connected to " + HOST + ":" + PORT);

                KeyPair keys = RSA.generateKeyPair();
                PrivateKey privateKey = keys.getPrivate();
                PublicKey publicKey = keys.getPublic();

                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                // Exchange keys
                PublicKey serverPublicKey = RSA.base64ToPublicKey(in.readLine());
                out.println(RSA.publicKeyToBase64(publicKey));

                // Send encrypted nickname
                out.println(RSA.encrypt(nickname, serverPublicKey));

                System.out.println("[Client] Secure connection established. You can start chatting!");
                System.out.println("Type 'exit' to leave.\n");

                // Thread to receive messages
                new Thread(() -> {
                    try {
                        String incoming;
                        while ((incoming = in.readLine()) != null) {
                            String message = RSA.decrypt(incoming, privateKey);
                            if (message.contains("Disconnecting")) {
                                System.out.println(message);
                                System.exit(0);
                            }
                            System.out.println("\n" + message);
                            System.out.print(nickname + ": ");
                        }
                    } catch (Exception e) {
                        System.out.println("[Client] Disconnected.");
                        System.exit(0);
                    }
                }).start();

                // Sending loop
                while (true) {
                    System.out.print(nickname + ": ");
                    String message = scanner.nextLine();
                    if (message.equalsIgnoreCase("exit")) break;
                    out.println(RSA.encrypt(message, serverPublicKey));
                }

            } catch (ConnectException e) {
                System.err.println("[Client Error] Could not connect. Make sure the server is running.");
            } catch (Exception e) {
                System.err.println("[Client Error] " + e.getMessage());
            }
        }
    }

    // ==============================================================
    // 🚀 Main Entry Point
    // ==============================================================
    public static void main(String[] args) {
        String mode = (args.length > 0) ? args[0].toLowerCase() : "server";
        if (mode.equals("server")) {
            ChatServer.start();
        } else if (mode.equals("client")) {
            ChatClient.start();
        } else {
            System.out.println("Invalid mode. Use 'server' or 'client'.");
        }
    }
}
