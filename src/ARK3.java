import edu.rit.util.Packing;

/**
 * An implementation of the ARK3 block cipher
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 *         3/17/2015
 */
public class ARK3 implements BlockCipher {

    private long[] subKeys = new long [28];

    /**
     * Returns this block cipher's block size in bytes.
     *
     * @return Block size.
     */
    @Override
    public int blockSize() {
        return 8;
    }

    /**
     * Returns this block cipher's key size in bytes.
     *
     * @return Key size.
     */
    @Override
    public int keySize() {
        return 16;
    }

    /**
     * Calculate all of the subkeys using the key schedule defined in the spec
     *
     * @param key the 128 iut key
     */
    @Override
    public void setKey(byte[] key) {
        for(int round = 1; round <= 27; round++) {
            // rotate key state 29 bits to the right
            long keyUpper = Packing.packLongBigEndian(key, 0);
            long keyLower = Packing.packLongBigEndian(key, 8);
            long keyLowerCopy = keyLower;
            keyLower >>>= 29;
            keyLower |= keyUpper << 35;
            keyUpper >>>= 29;
            keyUpper |= keyLowerCopy << 35;
            // send 8 most significant bytes through the substitution-permutation layer
            keyUpper = substitutionPermutation(keyUpper);
            // result of sub-permutation is subKeys
            subKeys[round] = keyUpper;
            // put result back in the state
            byte[] tempState = new byte[key.length];
            Packing.unpackLongBigEndian(keyUpper, tempState, 0);
            Packing.unpackLongBigEndian(keyLower, tempState, 8);
            // least significant bit XOR round number is the new key state
            tempState[15] ^= round;
            key = tempState;
        }
    }

    /**
     * Encrypt the plaintext bytes given in text (64 bytes)
     *
     * @param text plaintext to encrypt
     */
    @Override
    public void encrypt(byte[] text) {
        long data = Packing.packLongBigEndian(text, 0);
        for (int round = 1; round <= 27; round++) {
            // Subkey addition
            data ^= subKeys[round];
            data = substitutionPermutation(data);
        }
        Packing.unpackLongBigEndian(data, text, 0);
    }

    /**
     * Decrypt the given plaintext. <TT>text</TT> must be an array of bytes
     * whose length is equal to <TT>blockSize()</TT>. On input, <TT>text</TT>
     * contains the ciphertext block. The ciphertext block is decrypted using
     * the key specified in the most recent call to <TT>setKey()</TT>. On
     * output, <TT>text</TT> contains the plaintext block.
     *
     * @param text Ciphertext (on input), plaintext (on output).
     */
    @Override
    public void decrypt(byte[] text) {
        // unimplemented for this project
    }


    /**
     * Puts the input through the S-Boxes, permutes the bits, and mixes according to the spec.
     * Used by round function and key schedule.
     *
     * @param inputState the input to the substitutionPermutation function
     * @return the result of the substitutionPermutation
     */
    private long substitutionPermutation(long inputState) {
        byte[] currentStateByte = new byte[8];
        Packing.unpackLongBigEndian(inputState, currentStateByte, 0);
        // send state through S-boxes
        byte[] sBoxOutput = new byte[8];
        for(int i = 0; i < 8; i++) {
            sBoxOutput[i] = (byte) sBox(i + 1, currentStateByte[i]);
        }
        // permute s-box outputs
        currentStateByte[0] = sBoxOutput[5];
        currentStateByte[1] = sBoxOutput[0];
        currentStateByte[2] = sBoxOutput[3];
        currentStateByte[3] = sBoxOutput[6];
        currentStateByte[4] = sBoxOutput[1];
        currentStateByte[5] = sBoxOutput[4];
        currentStateByte[6] = sBoxOutput[7];
        currentStateByte[7] = sBoxOutput[2];
        // mix function
        for(int i = 0; i < 8; i += 2) {
            byte[] temp = mix(currentStateByte[i], currentStateByte[i + 1]);
            currentStateByte[i] = temp[0];
            currentStateByte[i + 1] = temp[1];
        }
        // pack the array into a long and return
        return Packing.packLongBigEndian(currentStateByte, 0);
    }

    /**
     * Performs a single S-box substitution, assuming GF(2^8).
     * Each S-box S_i(a) = ((x^7 + x^6) + i) * a + (x^6 + x^5 + x + 1)
     *
     * @param i index of S-box (treated as GF(2^8) polynomial)
     * @param a input of S-box (integer representation of GF(2^8) polynomial)
     * @return the output of the S-box
     */
    private int sBox(int i, int a) {
        // two GF(2^8) constants used in S-box
        int constant1 = 0xC0;
        int constant2 = 0x63;
        return GF28.galoisFieldMultiplication((constant1 ^ i), a) ^ constant2;

    }

    /**
     * Mixes two bytes of input as specified in the ARK3 spec
     *
     * @param a the first byte
     * @param b the second byte
     * @return an array of the results of the mix operation, element 0 is "c", element 1 is "d"
     */
    private byte[] mix(byte a, byte b) {
        byte[] result = new byte[2];
        int c;
        int d;
        int constant1 = 0x2;
        int constant2 = 0x3;
        c = GF28.galoisFieldMultiplication(constant1, a) ^ b;
        d = a ^ GF28.galoisFieldMultiplication(constant2, b);
        result[0] = (byte) c;
        result[1] = (byte) d;
        return result;
    }
}
