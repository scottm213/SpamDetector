package org.example;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SignatureDetector {

    private static final Set<String> hashDB = new HashSet<>();

    /**
     * Reads hashes.txt from the src/main/resources folder.
     */
    public static void loadHashes() {
        // The "/" points to the root of the resources folder
        try (InputStream is = SignatureDetector.class.getResourceAsStream("/hashes.txt")) {
            
            if (is == null) {
                throw new RuntimeException("Resource not found: hashes.txt. Ensure it is in src/main/resources/");
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                hashDB.clear(); // Clear existing to prevent duplicates if reloaded
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty()) {
                        hashDB.add(line);
                    }
                }
            }
            //System.out.println("Successfully loaded " + hashDB.size() + " signatures from resources.");

        } catch (Exception e) {
            System.err.println("Error reading hashes.txt: " + e.getMessage());
        }
    }

    public static String hash(String input) {
        try {

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(input.getBytes(StandardCharsets.UTF_8));


            try (InputStream is = SignatureDetector.class.getResourceAsStream("/hashes.txt")) {

                if (is == null) {
                    throw new RuntimeException("Resource not found: hashes.txt. Ensure it is in src/main/resources/");
                }


                //System.out.println("Successfully loaded " + hashDB.size() + " signatures from resources.");

            } catch (Exception e) {
                System.err.println("Error reading hashes.txt: " + e.getMessage());
            }


            StringBuilder hexString = new StringBuilder();
            for (byte b : encodedhash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            //System.out.println(hexString);
            return hexString.toString();

        } catch (Exception e) {
            throw new RuntimeException("Hashing error", e);
        }
    }

    public static boolean isSpam(String emailContent) {
        // Auto-load if the database is empty
        if (hashDB.isEmpty()) {
            loadHashes();
        }
        return hashDB.contains(hash(emailContent));
    }
}