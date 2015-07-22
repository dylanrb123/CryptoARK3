/**
 * Cipher Feedback Mode for ARK3 cipher, implemented as a stream cipher
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 * 3/17/2015
 */
public class ARK3CFB implements StreamCipher {

    private ARK3 encryptor = new ARK3();
    private byte[] keystream = new byte [8];
    private int k;

    /**
     * Returns this stream cipher's key size in bytes. If the stream cipher
     * includes both a key and a nonce, <TT>keySize()</TT> returns the size of
     * the key plus the nonce in bytes.
     *
     * @return Key size.
     */
    @Override
    public int keySize() {
        return 16 + 8; // 16 key bytes, 8 nonce bytes
    }

    /**
     * Sets the key of the block cipher and initializes the keystream of the stream cipher
     *
     * @param key the key and initialization vector. key[0] - key[16] are the key, key[16] - key[32] are the IV
     */
    @Override
    public void setKey(byte[] key) {
        byte[] cipherKey = new byte[16];
        System.arraycopy(key, 0, cipherKey, 0, 16);
        encryptor.setKey(cipherKey);
        System.arraycopy(key, 16, keystream, 0, 8); // copy initialization vector into keystream
        k = 8;
    }

    /**
     * Encrypt the given byte.
     *
     * @param workingByte Byte to encrypt or decrypt
     * @return ciphertext byte/plaintext byte (depending on whether encrypting or decrypting
     */
    @Override
    public int encrypt(int workingByte) {
        if (k == 8)
        {
            encryptor.encrypt (keystream);
            k = 0;
        }
        int returnVal = workingByte ^ keystream[k];
        keystream[k] = (byte) returnVal;
        k++;
        return returnVal;
    }

    /**
     * Decrypt the given byte. Only the least significant 8 bits of <TT>b</TT>
     * are used. The plaintext byte is returned as a value from 0 to 255.
     *
     * @param workingByte Ciphertext byte.
     * @return Plaintext byte.
     */
    @Override
    public int decrypt(int workingByte) {
        if (k == 8)
        {
            encryptor.encrypt (keystream);
            k = 0;
        }
        int returnVal = workingByte ^ keystream[k];
        keystream[k] = (byte) workingByte;
        k++;
        return returnVal;
    }
}