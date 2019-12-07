/**
 * KeyExpander - this class expands an initial 128-bit Key into ten additional keys
 * needed for AES encryption.
 *
 * NOTE: Keys are displayed in row-major order, not column-major order (which is sometimes used).
 * Thus, the keys for the SECOND TEST are correct, which you can see by writing each key and its example into a state matrix and
 * comparing them.
 *
 * @author Seb Kryspin
 * @version 1.0
 */

public class KeyExpander {

  private short[][] roundKeys = new short[4][44]; //a set of round keys

  //the Rijndael sBox, used for SubBytes()
  private static short[][] sBox =
	{{0x63,	0x7c,	0x77,	0x7b,	0xf2,	0x6b,	0x6f,	0xc5,	0x30,	0x01,	0x67,	0x2b,	0xfe,	0xd7,	0xab,	0x76},
	{0xca,	0x82,	0xc9,	0x7d,	0xfa,	0x59,	0x47,	0xf0,	0xad,	0xd4,	0xa2,	0xaf,	0x9c,	0xa4,	0x72,	0xc0},
	{0xb7,	0xfd,	0x93,	0x26,	0x36,	0x3f,	0xf7,	0xcc,	0x34,	0xa5,	0xe5,	0xf1,	0x71,	0xd8,	0x31,	0x15},
	{0x04,	0xc7,	0x23,	0xc3,	0x18,	0x96,	0x05,	0x9a,	0x07,	0x12,	0x80,	0xe2,	0xeb,	0x27,	0xb2,	0x75},
	{0x09,	0x83,	0x2c,	0x1a,	0x1b,	0x6e,	0x5a,	0xa0,	0x52,	0x3b,	0xd6,	0xb3,	0x29,	0xe3,	0x2f,	0x84},
	{0x53,	0xd1,	0x00,	0xed,	0x20,	0xfc,	0xb1,	0x5b,	0x6a,	0xcb,	0xbe,	0x39,	0x4a,	0x4c,	0x58,	0xcf},
	{0xd0,	0xef,	0xaa,	0xfb,	0x43,	0x4d,	0x33,	0x85,	0x45,	0xf9,	0x02,	0x7f,	0x50,	0x3c,	0x9f,	0xa8},
	{0x51,	0xa3,	0x40,	0x8f,	0x92,	0x9d,	0x38,	0xf5,	0xbc,	0xb6,	0xda,	0x21,	0x10,	0xff,	0xf3,	0xd2},
	{0xcd,	0x0c,	0x13,	0xec,	0x5f,	0x97,	0x44,	0x17,	0xc4,	0xa7,	0x7e,	0x3d,	0x64,	0x5d,	0x19,	0x73},
	{0x60,	0x81,	0x4f,	0xdc,	0x22,	0x2a,	0x90,	0x88,	0x46,	0xee,	0xb8,	0x14,	0xde,	0x5e,	0x0b,	0xdb},
	{0xe0,	0x32,	0x3a,	0x0a,	0x49,	0x06,	0x24,	0x5c,	0xc2,	0xd3,	0xac,	0x62,	0x91,	0x95,	0xe4,	0x79},
	{0xe7,	0xc8,	0x37,	0x6d,	0x8d,	0xd5,	0x4e,	0xa9,	0x6c,	0x56,	0xf4,	0xea,	0x65,	0x7a,	0xae,	0x08},
	{0xba,	0x78,	0x25,	0x2e,	0x1c,	0xa6,	0xb4,	0xc6,	0xe8,	0xdd,	0x74,	0x1f,	0x4b,	0xbd,	0x8b,	0x8a},
	{0x70,	0x3e,	0xb5,	0x66,	0x48,	0x03,	0xf6,	0x0e,	0x61,	0x35,	0x57,	0xb9,	0x86,	0xc1,	0x1d, 0x9e},
	{0xe1,	0xf8,	0x98,	0x11,	0x69,	0xd9,	0x8e,	0x94,	0x9b,	0x1e,	0x87,	0xe9,	0xce,	0x55,	0x28,	0xdf},
	{0x8c,	0xa1,	0x89,	0x0d,	0xbf,	0xe6,	0x42,	0x68, 0x41,	0x99,	0x2d,	0x0f,	0xb0,	0x54,	0xbb,	0x16}};

  private static short[][] rCon = {{0x01, 0x02, 0x04, 0x08, 0x10,0x20,0x40,0x80,0x1b,0x36}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}; //the roundconstant array



  /**
   * Generates an additional 10 keys from an initial Key.
   *
   * @param k an initial Key
   */
  public KeyExpander(Key k) {
    byte row = 0;
    byte column = 0;

    for (row = 0; row < 4; row++)
      for (column = 0; column < 4; column++)
        roundKeys[row][column] = k.getKeyValue()[row][column]; //fills in the initial key

    byte round = 0;
    for (column = 4; column < 44; column++) { //calculates the additional keys
      if (column % 4 == 0) {
        RotWord(column-1, column);

        SubBytes(column);

        XORandRcon(column, round);
        round++;
      }
      else {
        XORColumns(column-1, column-4, column);
      }
    }
  }

  /**
   * Returns the ith key generated from the key expansion algorithm.
   *
   * @param i the round number
   * @return the key for round i in AES encryption, as a 2d short array
   */
  public short[][] getRoundKey(int i) {
    int cStart = i*4;
    int cEnd = cStart + 4;
    short[][] result = new short[4][4];
    int resultColumn = 0;
    for (int row = 0; row < 4; row++){
      resultColumn = 0;
      for (int column = cStart; column < cEnd; column++) {
        result[row][resultColumn] = roundKeys[row][column];
        resultColumn++;
      }
    }
    return result;
  }

  /**
   * Puts the oldColumn, rotated by 1 byte, into the newColumn of roundKeys
   *
   * @param column the column to rotate, as an index
   * @param the new column to create with the rotated column, as an index
   */
  private void RotWord(int oldColumn, int newColumn) {
    for (int row = 0; row < 3; row++)
      roundKeys[row][newColumn] = roundKeys[row+1][oldColumn];
    roundKeys[3][newColumn] = roundKeys[0][oldColumn];
  }


  /**
   * Computes  c1 XOR c2 and puts the result in roundKeys' newColumn
   *
   * @param a column of roundKeys to xor
   * @param a column of roundKeys to xor
   * @param a column of roundKeys to put the result in
   */
  private void XORColumns(int c1, int c2, int newColumn) {
    for (int row = 0; row < 4; row++) {
      int intermediate = roundKeys[row][c1] ^ roundKeys[row][c2];
      roundKeys[row][newColumn] = new Integer(intermediate).shortValue(); //have to manually convert to a short
    }
  }

  /**
   * Substitutes all bytes in roundKeys newColumn using the S-box
   *
   * @param newColumn the int value of the column to substitute
   */
  private void SubBytes(int newColumn) {
    for (int row = 0; row < 4; row++) {
      short value = roundKeys[row][newColumn];
      roundKeys[row][newColumn] = sBox[highNibble(value)][lowNibble(value)];
    }
  }

  /**
   * XORS the newColumn with the appropriate column (i-4) and the appropriate
   * rCon and puts the result in newColumn.
   *
   * This operation should only be used when newColumn is a multiple of 4 as part
   * of the key expansion algorithm.
   * @param newColumn the column to manipulate
   * @param round the round of expansion we are on, so we can use the correct rCon
   */
  private void XORandRcon(int newColumn, int round) {
    for (int row = 0; row < 4; row++) {
      int old = roundKeys[row][newColumn-4];
      int newVal = roundKeys[row][newColumn];
      int intermediate = (old^newVal^rCon[row][round]);
      roundKeys[row][newColumn] = new Integer(intermediate).shortValue(); //had to manually convert it to get around Java's weird Binary Numeric Promotion
    }
  }

  /**
   * Returns the top nibble of a byte value.
   *
   * NOTE: Returns the top nibble for an 8-bit value only.
   *
   * @param x the byte we are considering (as a short)
   * @return the top nibble
   */
  public static int highNibble(short x) {
    return ((short) 0xf0 & (short) x)>>4;
  }

  /**
   * Returns the low nibble of a byte value.
   *
   * NOTE: Returns the low nibble for an 8-bit value only.
   *
   * @param x the byte we are considering (as a short)
   * @return the lowest nibble
   */
  public static int lowNibble(short x) {
    return ((short) 0xf & (short) x);
  }


  /**
   * Prints the ith round key
   *
   * @param i the round number
   */
  private void printRoundKey(int i) {
    System.out.println(new Key(getRoundKey(i)));  //prints the ith round key as a key
  }



  /**
   * Tests KeyExpander using the Rijndael inspector example and the AES
   * powerpoint example (https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf)
   *
   * The correctness of the keys can be verified by comparing the results to
   * those sources. Note that we print keys in row-major order, but the kavaliro
   * link prints keys in column-major order - so our results are equivalent.
   *
   */
  public static void main(String[] args) {
    //FIRST TEST (from Rijndael inspector)
    short[][] sampleKey1 ={{0x2b, 0x28, 0xab, 0x09}, {0x7e, 0xae, 0xf7, 0xcf}, {0x15, 0xd2, 0x15, 0x4f}, {0x16, 0xa6, 0x88, 0x3c}};
    Key k1 = new Key(sampleKey1);
    KeyExpander expand1 = new KeyExpander(k1); //expands key k
    for (int i = 0; i < 11; i++)
      expand1.printRoundKey(i); //prints each round key


    System.out.println("\n");
    //SECOND TEST (from https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf)
    short[][] sampleKey2 ={{0x54, 0x73, 0x20, 0x67},
                           {0x68, 0x20, 0x4b, 0x20},
                           {0x61, 0x6d, 0x75, 0x46},
                           {0x74, 0x79, 0x6e, 0x75}};
    Key k2 = new Key(sampleKey2);
    KeyExpander expand2 = new KeyExpander(k2); //expands key k
    for (int i = 0; i < 11; i++)
      expand2.printRoundKey(i); //prints each round key
  }
}
