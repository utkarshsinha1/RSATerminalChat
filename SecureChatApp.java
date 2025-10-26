import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;

/**
 * SecureChatApp: Multi-client, RSA-encrypted chat application.
 *
 * To run:
 * 1. Compile: javac SecureChatApp.java
 * 2. Start Server: java SecureChatApp (Server mode is now the default)
 * 3. Start Client(s): java SecureChatApp client
 *
 * It uses 1024-bit RSA encryption for key exchange and message encryption on port 3000.
 * NOTE: Messages must be kept short (under ~100 characters) due to RSA limits.
 */
public class SecureChatApp {

    private static final int PORT = 3000;
    private static final String HOST = "127.0.0.1";
    private static final int KEY_SIZE = 1024;
    private static final String ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";

    /**
     * Nested utility class to handle all RSA cryptographic operations.
     */
    private static class RSA {
        
        public static KeyPair generateKeyPair() throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEY_SIZE);
            return keyGen.generateKeyPair();
        }

        public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }

        public static String decrypt(String cipherTextBase64, PrivateKey privateKey) throws Exception {
            byte[] cipherText = Base64.getDecoder().decode(cipherTextBase64);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(cipherText);
            return new String(decryptedBytes, "UTF-8");
        }

        public static String publicKeyToBase64(PublicKey publicKey) {
            return Base64.getEncoder().encodeToString(publicKey.getEncoded());
        }

        public static PublicKey base64ToPublicKey(String base64Key) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
    }

    /**
     * The Multi-threaded Server component.
     */
    private static class ChatServer {
        
        // Maps Nickname to Client connection details (Public Key and Writer)
        private static final ConcurrentHashMap<String, ClientHandler> activeClients = new ConcurrentHashMap<>();
        private static KeyPair serverKeyPair;
        
        /**
         * Dedicated thread class for handling a single client connection.
         */
        private static class ClientHandler implements Runnable {
            private Socket socket;
            private PublicKey clientPublicKey;
            private PrintWriter out;
            private BufferedReader in;
            private String clientName;

            public ClientHandler(Socket socket) throws IOException {
                this.socket = socket;
                this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                this.out = new PrintWriter(socket.getOutputStream(), true);
            }

            // Sends a message to this specific client, encrypting it first
            public void sendEncryptedMessage(String message) {
                try {
                    String cipherText = RSA.encrypt(message, clientPublicKey);
                    out.println(cipherText);
                } catch (Exception e) {
                    System.err.println("[SERVER ERROR] Failed to encrypt/send to " + clientName + ": " + e.getMessage());
                }
            }

            @Override
            public void run() {
                try {
                    // --- 1. Key Exchange ---
                    // A. Send Server Public Key
                    out.println(RSA.publicKeyToBase64(serverKeyPair.getPublic()));
                    
                    // B. Receive Client Public Key
                    String clientPubKeyBase64 = in.readLine();
                    clientPublicKey = RSA.base64ToPublicKey(clientPubKeyBase64);
                    
                    // --- 2. Receive Nickname ---
                    String encryptedName = in.readLine();
                    // The client encrypts their name using the server's public key
                    clientName = RSA.decrypt(encryptedName, serverKeyPair.getPrivate());

                    if (clientName == null || clientName.trim().isEmpty() || activeClients.containsKey(clientName)) {
                        sendEncryptedMessage("[SERVER]: Nickname is invalid or already taken. Disconnecting.");
                        return;
                    }

                    // --- 3. Register Client and Announce ---
                    activeClients.put(clientName, this);
                    System.out.println("[SERVER] " + clientName + " connected from: " + socket.getInetAddress());
                    broadcast("[SERVER]: " + clientName + " has joined the chat.");
                    
                    // --- 4. Main Message Loop ---
                    String cipherTextBase64;
                    while ((cipherTextBase64 = in.readLine()) != null) {
                        if (cipherTextBase64.isEmpty()) continue;
                        
                        // Decrypt the message using the server's private key
                        String decryptedMessage = RSA.decrypt(cipherTextBase64, serverKeyPair.getPrivate());
                        
                        String broadcastMessage = "[" + clientName + "]: " + decryptedMessage;
                        System.out.println("[SERVER LOG] Broadcast: " + broadcastMessage);
                        broadcast(broadcastMessage);
                    }

                } catch (SocketException se) {
                    // Client closed the socket
                } catch (Exception e) {
                    System.err.println("[SERVER ERROR] Handler for " + clientName + ": " + e.getMessage());
                } finally {
                    // --- 5. Cleanup ---
                    if (clientName != null) {
                        activeClients.remove(clientName);
                        System.out.println("[SERVER] " + clientName + " has disconnected.");
                        // Inform remaining clients
                        broadcast("[SERVER]: " + clientName + " has left the chat.");
                    }
                    try { socket.close(); } catch (IOException ignored) {}
                }
            }
        }

        // Broadcasts a plaintext message to ALL connected clients (re-encrypting for each).
        private static void broadcast(String message) {
            for (ClientHandler handler : activeClients.values()) {
                handler.sendEncryptedMessage(message);
            }
        }

        public static void start() {
            ServerSocket serverSocket = null;
            try {
                // 1. Generate Server Keys (only once)
                serverKeyPair = RSA.generateKeyPair();
                System.out.println("[SERVER] RSA Key Pair generated. Listening on port " + PORT + "...");

                // 2. Start Server Socket and wait for Clients indefinitely
                serverSocket = new ServerSocket(PORT);
                
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    // Start a new thread for each client
                    new Thread(new ClientHandler(clientSocket)).start();
                }

            } catch (Exception e) {
                System.err.println("[SERVER FATAL ERROR] " + e.getMessage());
            } finally {
                if (serverSocket != null) {
                    try { serverSocket.close(); } catch (IOException ignored) {}
                }
            }
        }
    }

    /**
     * The Client component of the chat application.
     */
    private static class ChatClient {
        public static void start() {
            Socket socket = null;
            Scanner consoleScanner = new Scanner(System.in);
            String clientName = null;
            
            // 1. Get Nickname
            while (clientName == null || clientName.trim().isEmpty()) {
                System.out.print("[CLIENT SETUP] Enter your nickname: ");
                clientName = consoleScanner.nextLine();
            }

            // --- FIX START ---
            // Create an effectively final copy of clientName for use in the lambda (receiverThread)
            final String promptName = clientName; 
            // --- FIX END ---

            try {
                // 2. Generate Client Keys
                KeyPair pair = RSA.generateKeyPair();
                PrivateKey clientPrivateKey = pair.getPrivate();
                PublicKey clientPublicKey = pair.getPublic();
                PublicKey serverPublicKey; // Server's public key

                System.out.println("[CLIENT] RSA Key Pair generated. Nickname set to: " + clientName);

                // 3. Connect to Server
                System.out.println("[CLIENT] Connecting to Server at " + HOST + ":" + PORT + "...");
                socket = new Socket(HOST, PORT);
                System.out.println("[CLIENT] Successfully connected to server.");

                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                // --- 4. Key and Name Exchange Protocol ---
                // A. Receive Server Public Key
                String serverPubKeyBase64 = in.readLine();
                serverPublicKey = RSA.base64ToPublicKey(serverPubKeyBase64);
                
                // B. Send Client Public Key
                out.println(RSA.publicKeyToBase64(clientPublicKey));

                // C. Send Encrypted Nickname
                // The client encrypts its name using the server's public key for initial security
                String encryptedName = RSA.encrypt(clientName, serverPublicKey);
                out.println(encryptedName);
                
                System.out.println("[CLIENT] Secure chat link established. Welcome!");


                // 5. Start Chat Threads
                
                // Receiver Thread
                Thread receiverThread = new Thread(() -> {
                    try {
                        String cipherTextBase64;
                        while ((cipherTextBase64 = in.readLine()) != null) {
                            if (cipherTextBase64.isEmpty()) continue;
                            // Decrypt using the client's private key
                            String decryptedMessage = RSA.decrypt(cipherTextBase64, clientPrivateKey);
                            
                            // Check for disconnection message from server
                            if (decryptedMessage.contains("Disconnecting")) {
                                System.out.println(decryptedMessage);
                                System.exit(0);
                            }
                            
                            // Print incoming message (which is already formatted by the server)
                            System.out.println("\n" + decryptedMessage);
                            System.out.print(promptName + ": "); // Use the effectively final variable
                        }
                    } catch (SocketException se) {
                        System.out.println("\n[CLIENT] Connection closed by the server.");
                    } catch (Exception e) {
                        System.err.println("\n[CLIENT ERROR] Receiver: " + e.getMessage());
                    } finally {
                        System.exit(0);
                    }
                });
                receiverThread.start();

                // Main loop for sending messages
                System.out.println("\n*** CHAT STARTED ***\nType 'exit' to quit.\n");
                while (true) {
                    System.out.print(promptName + ": "); // Use the effectively final variable
                    String message = consoleScanner.nextLine();

                    if (message.equalsIgnoreCase("exit")) {
                        socket.close();
                        break;
                    }

                    // Client sends only the raw message, encrypted using the SERVER's public key.
                    String cipherTextBase64 = RSA.encrypt(message, serverPublicKey);
                    out.println(cipherTextBase64);
                }

            } catch (ConnectException ce) {
                System.err.println("[CLIENT FATAL ERROR] Connection refused. Ensure the server is running on port " + PORT + ".");
            } catch (Exception e) {
                System.err.println("[CLIENT FATAL ERROR] " + e.getMessage());
            } finally {
                if (socket != null) {
                    try { socket.close(); } catch (IOException ignored) {}
                }
            }
        }
    }

    /**
     * Main method to route execution to either the server or client based on arguments.
     * Defaults to 'server' mode if no argument is provided.
     */
    public static void main(String[] args) {
        // Default mode is 'server'
        String mode = "server"; 
        
        if (args.length > 0) {
            mode = args[0].toLowerCase();
        } else {
             System.out.println("No mode specified. Defaulting to SERVER mode on port " + PORT + ".");
        }

        if (mode.equals("server")) {
            ChatServer.start();
        } else if (mode.equals("client")) {
            ChatClient.start();
        } else {
            System.out.println("Invalid mode specified. Use 'server' or 'client'.");
        }
    }
}
