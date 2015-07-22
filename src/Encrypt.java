import edu.rit.util.Hex;

import java.io.*;

/**
 * Encryption main class for Project 2. Performs file IO and uses the ARK3 cipher to encrypt the file.
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 */
public class Encrypt {

    public static final int KEY_LENGTH = 32;
    public static final int IV_LENGTH = 16;

    /**
     * Main method. Encrypts a file byte-by-byte using ARK3 cipher in CFB mode.
     *
     * @param args command line arguments.
     *             args[0] is the plaintext file name
     *             args[1] is the ciphertext file name
     *             args[2] is the key (32 Hex digits)
     *             args[3] is the initialization vector (16 Hex digits)
     */
    public static void main(String[] args) {
        if (args.length != 4) usage();
        File plaintextFileName = new File (args[0]);
        File ciphertextFileName = new File (args[1]);

        if(!isValidKeyAndIv(args[2], args[3])) {
            System.err.println("Invalid key or IV");
            System.exit(1);
        }
        byte[] key = Hex.toByteArray(args[2]);
        byte[] iv = Hex.toByteArray(args[3]);
        byte[] keyAndIv = new byte[key.length + iv.length];
        System.arraycopy(key, 0, keyAndIv,0, key.length);
        System.arraycopy(iv, 0, keyAndIv, key.length, iv.length);

        ARK3CFB encryptor = new ARK3CFB();
        encryptor.setKey(keyAndIv);

        InputStream plaintextStream = null;
        OutputStream ciphertextStream = null;
        try {
            plaintextStream = new BufferedInputStream(new FileInputStream(plaintextFileName));
        } catch (FileNotFoundException e) {
            System.err.println("Plaintext file " + plaintextFileName + " not found");
            System.exit(1);
        }
        try {
            ciphertextStream = new BufferedOutputStream(new FileOutputStream(ciphertextFileName));
        } catch (FileNotFoundException e) {
            System.err.println("Unable to create ciphertext file " + ciphertextFileName);
            System.exit(1);
        }
        int plaintextByte;
        try {
            while ((plaintextByte = plaintextStream.read()) != -1) {
                int out = encryptor.encrypt(plaintextByte);
                ciphertextStream.write(out);
            }
        } catch (IOException e) {
            System.err.println("Error writing or reading files");
            System.exit(1);
        } finally {
            try {
                plaintextStream.close();
                ciphertextStream.close();
            } catch (IOException e) {
                System.err.println("Error closing streams");
                System.exit(1);
            }
        }
    }

    /**
     * Verifies that the key and IV are valid
     *
     * @param key the key given as a command line arg
     * @param iv the IV given as a command line arg
     * @return true if the key and IV are valid, else false
     */
    private static boolean isValidKeyAndIv(String key, String iv) {
        if(key.length() != KEY_LENGTH || iv.length() != IV_LENGTH) {
            return false;
        }
        for(Character c : key.toCharArray()) {
            if(Character.digit(c, 16) == -1) {
                return false;
            }
        }
        for(Character c : iv.toCharArray()) {
            if(Character.digit(c, 16) == -1) {
                return false;
            }
        }
        return true;
    }

    /**
     * Print a usage message and exit.
     */
    private static void usage()
    {
        System.err.println("Usage: java Encrypt <PlaintextFile> <CiphertextFile> <Key> <IV>");
        System.err.println("<PlaintextFile> = Plaintext file name");
        System.err.println("<CiphertextFile> = Ciphertext file name");
        System.err.println("<Key> = Key (32 hex digits)");
        System.err.println("<IV> = Initialization vector (IV) (16 hex digits");
        System.exit(1);
    }
}
