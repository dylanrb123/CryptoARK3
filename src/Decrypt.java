import edu.rit.util.Hex;

import java.io.*;

/**
 * Decryption main class for Project 2. Performs file IO and uses the ARK3 cipher to decrypt the file.
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 */
public class Decrypt {

    public static final int KEY_LENGTH = 32;
    public static final int IV_LENGTH = 16;

    /**
     * Main method. Decrypts a file byte-by-byte using ARK3 cipher in CFB mode.
     *
     * @param args command line arguments.
     *             args[0] is the ciphertext file name
     *             args[1] is the plaintext file name
     *             args[2] is the key (32 Hex digits)
     *             args[3] is the initialization vector (16 Hex digits)
     */
    public static void main(String[] args) {
        if (args.length != 4) usage();
        File ciphertextFile = new File (args[0]);
        File plaintextFile = new File (args[1]);

        if(!isValidKeyAndIv(args[2], args[3])) {
            System.err.println("Invalid key or IV");
            System.exit(1);
        }
        byte[] key = Hex.toByteArray(args[2]);
        byte[] iv = Hex.toByteArray(args[3]);
        byte[] keyAndIv = new byte[key.length + iv.length];
        System.arraycopy(key, 0, keyAndIv,0, key.length);
        System.arraycopy(iv, 0, keyAndIv, key.length, iv.length);

        ARK3CFB decryptor = new ARK3CFB();
        decryptor.setKey(keyAndIv);

        InputStream ciphertextStream = null;
        OutputStream plaintextStream = null;

        try {
            ciphertextStream = new BufferedInputStream(new FileInputStream(ciphertextFile));
        } catch (FileNotFoundException e) {
            System.err.println("Plaintext file " + ciphertextFile + " not found");
            System.exit(1);
        }
        try {
            plaintextStream = new BufferedOutputStream(new FileOutputStream(plaintextFile));
        } catch (FileNotFoundException e) {
            System.err.println("Unable to create ciphertext file " + plaintextFile);
            System.exit(1);
        }
        int ciphertextByte;
        try {
            while ((ciphertextByte = ciphertextStream.read()) != -1) {
                int out = decryptor.decrypt(ciphertextByte);
                plaintextStream.write(out);
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
        System.err.println("Usage: java Decrypt <CiphertextFile> <PlaintextFile> <Key> <IV>");
        System.err.println("<CiphertextFile> = Ciphertext file name");
        System.err.println("<PlaintextFile> = Plaintext file name");
        System.err.println("<Key> = Key (32 hex digits)");
        System.err.println("<IV> = Initialization vector (IV) (16 hex digits");
        System.exit(1);
    }
}
