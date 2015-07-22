/**
 * @author Dylan Bannon <drb2857@rit.edu>
 *         3/30/2015
 */
public class GF28 {
    /**
     * Performs GF(2^8) multiplication on the given polynomials represented as 32 bit
     * integers, using x^8 + x^4 + x^3 + x^2 + 1 as the irreducible polynomial.
     *
     * @param a The multiplicand polynomial
     * @param b The multiplier polynomial
     * @return The result of the GF(2^8) multiplication of the arguments
     */
    public static int galoisFieldMultiplication(int a, int b) {
        int irreducible = 0x11D;
        int result = 0;
        for (int bit = 0x80; bit > 0; bit >>= 1) {
            result <<= 1;
            if((result & 0x100) != 0) {
                result ^= irreducible;
            }
            if((b & bit) != 0) {
                result ^= a;
            }
        }
        return result;
    }
}
