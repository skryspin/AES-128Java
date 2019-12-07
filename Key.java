import java.security.SecureRandom;

/*
 * Key - defines a key. This class mostly exists so that Keys can be easily
 * printed for testing purposes. It can also generate a random key.
 *
 * @see KeyExpander
 * @see SecureRandom
 * @author Seb Kryspin
 * @version 1.0
 */
public class Key {
  private short[][] keyValue = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}}; //I used short since java Bytes are signed which does not allow the appropriate hex values to be stored

  /**
   * Generates a cryptographically secure random Key.
   *
   */
  public Key(){
    SecureRandom random = new SecureRandom();
    byte bytes[] = new byte[16];
    random.nextBytes(bytes);
    int b = 0;
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        keyValue[i][j] = (new Integer(bytes[b] & 0xff)).shortValue();
        b++;
      }
    }
  }

  /**
   * Constructs a key object with the given 4x4 short[][].
   *
   * @param k the 2d short array to be made into a Key
   */
  public Key(short[][] k) {
    keyValue = k;
  }

  /**
   * Returns the keyValue as a short[4][4].
   *
   * @return the keyValue as a 4x4 short array
   */
  public short[][] getKeyValue() {return keyValue;}


  /**
   * Returns a represtation of a key as a String of hex values.
   *
   * @return a String of 16 hex values separated by spaces
   */

  public String toString() { //configures a key as a list of hex digits
    String result = "";
    for (short[] x: keyValue)
      for (short y: x)
        result = result + String.format("%02X", y) + " ";
    return result;
  }

}
