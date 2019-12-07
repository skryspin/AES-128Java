import java.util.Arrays;

/**
 * AESDecrypter decrypts a 4x4 short array of bytes and prints the resulting plaintext,
 * as well as each step along the way. You must provide a key with which to decrypt.
 *
 * @see Key
 * @see KeyExpander
 * @see AESEncrypter
 * @author Seb Kryspin
 * @version 1.0
 */

public class AESDecrypter {
  private KeyExpander expand; //key expander
  private short[][] stateMatrix = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}}; //the state matrix

  private static short[][] inverseSBox =
{{0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
{0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
{0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
{0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
{0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
{0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
{0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
{0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
{0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
{0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
{0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
{0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
{0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
{0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
{0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
{0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}};  //the inverse S-box

private static short[][] invMixMatrix = {{14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14}}; //the inverse mix matrix for InvMixColumns()


  /**
   * Constructs a new AESDecrypter in preparation for decryption with key k.
   *
   * @param k the key with which we will decrypt
   */
  public AESDecrypter(Key k) {
    expand = new KeyExpander(k);
  }

  /**
   * Decrypts the specified 4x4 array of ciphertext.
   *
   * @param ciphertext a 4x4 array of shorts
   * @return a new 4x4 array of shorts containing the decrypted message
   */
  public short[][] Decrypt(short[][] ciphertext){
    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
        stateMatrix[i][j] = ciphertext[i][j];
    InitialRoundDecrypt();
    for (int i = 9; i > 0; i--){
      NormalRoundDecrypt(i);
    }
    AddRoundKey(0);
    System.out.println("Removing the initial key.. ");
    printMatrix();
    short[][] plaintext = new short[4][4];
    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
        plaintext[i][j] = stateMatrix[i][j];
        /*This step is EXTREMELY important - we must DEEP COPY the stateMatrix to a
        new array plaintext. If we simply  return stateMatrix, all the variables
        that reference the returned object will refer to the same underlying array.
        This does not cause an issue when decrypting only once, but when decrypting
        multiple blocks with the same key (and thus the same AESEncrypter), as in
        Cipher Block Chaining mode, each decryption will overwrite the previous decryption,
        and thus if we later try to reference, say, an decrypted block i stored in
        some ArrayList of short[][]s, we will receive instead the decryption of the most
        recent block.

        Also: Note that using .clone() or .arrayCopy() will NOT solve this issue,
        since we are using a 2d array. So, the
        stateMatrix returned would contain a nice NEW array that contains
        references to the same four little arrays in stateMatrix. Thus, the same
        issue as above would result.

        This bug took over 7 hours to solve - take caution.

        This issue was first discovered in AESEncrypter and then analogously fixed here.
        */
    return plaintext;
  }

  /**
   * Performs the initial round of AES decryption (no InvMixColumns)
   *
   */
  private void InitialRoundDecrypt() {
    AddRoundKey(10);
    System.out.println("AddRoundKey initial round ");
    printMatrix();
    InvShiftRows();
    System.out.println("InvShiftRows initial round ");
    printMatrix();
    InvSubBytes();
    System.out.println("InvSubBytes initial round ");
    printMatrix();
  }

  /**
   * Performs a normal round of AES decryption (not initial or final)
   *
   * @param round the round number, which indicates which key we should use
   */
  private void NormalRoundDecrypt(int round) {
    AddRoundKey(round);
    System.out.println("Removing AddRoundKey from round " + round);
    printMatrix();
    InvMixColumns();
    System.out.println("Inverting MixColumns from round " + round);
    printMatrix();
    InvShiftRows();
    System.out.println("Inverting ShiftRows from round " + round);
    printMatrix();
    InvSubBytes();
    System.out.println("Inverting SubBytes from round " + round);
    printMatrix();
  }

  /**
   * Performs the InvShiftRows step of decryption. Cyclically shifts the last
   * three rows of the stateMatrix to the right by 1, 2, and 3 respectively.
   *
   */
  private void InvShiftRows() {
    /*Shifts row 1 right by 1, row 2 right by 2, and row 3 right by 3. Row 0 remains the same.*/
      //row 1, right shift by 1
      short temp = stateMatrix[1][3];
      for (int column = 3; column > 0; column--) {
        stateMatrix[1][column] = stateMatrix[1][column-1];
      }
      stateMatrix[1][0] = temp;

      /*row 2 right shift by 2 is the same as row 2 left shift by 2, so we use
      the same code from AESEncrypter's ShiftRows()*/
      int row = 2;
      short[] old2 = {stateMatrix[row][0], stateMatrix[row][1], stateMatrix[row][2], stateMatrix[row][3]};

      for (int column = 0; column < 4; column++) {
        stateMatrix[row][column] = old2[(column+2)%4];
      }

      /*row 3 right shift by 3 is the same as row 3, left shift by 1 so we use the left shift by 1
      from AESEncrypter's ShiftRows(), except on row 3 this time */
      temp = stateMatrix[3][0];
      for (int column = 0; column < 3; column++) {
        stateMatrix[3][column] = stateMatrix[3][column+1];
      }
      stateMatrix[3][3] = temp;
    }

    /**
     * Substitutes all bytes in the stateMatrix using the inverse S-box.
     *
     */
    private void InvSubBytes() {
      for (int row = 0; row < 4; row++) {
        for (int column = 0; column < 4; column++){
          short value = stateMatrix[row][column];
          stateMatrix[row][column] = inverseSBox[expand.highNibble(value)][expand.lowNibble(value)];
        }
      }
    }

  /**
   * XORs the ith round key with the stateMatrix, and updates the
   * state matrix.
   *
   * @param round the current round (0 to 10)
   */
  private void AddRoundKey(int round) {
    short[][] key = expand.getRoundKey(round);
    for (int row = 0; row < 4; row++) {
      for (int column = 0; column < 4; column++) {
        int intermediate = key[row][column] ^ stateMatrix[row][column];
        stateMatrix[row][column] = new Integer(intermediate).shortValue();
      }
    }
  }

  /**
   * Prints the current state matrix of a AESDecrypter.
   *
   */
  public void printMatrix() {
    for (int row = 0; row < 4; row++) {
      for (int column = 0; column < 4; column++) {
        System.out.print(Integer.toHexString(stateMatrix[row][column]) + " ");
      }
      System.out.println();
    }
  }

  /**
   * Performs the InvMixColumns() step of AES decryption.
   *
   */
  private void InvMixColumns() {
    for (int c = 0; c < 4; c++) {
      mixColumn(c);
    }
  }

  /**
   * Mixes a single column for InvMixColumns().
   * @param the column index
   */
  private void mixColumn(int stateColumn) {
    /*The code is the same as Encryption, it just calls InvGMultiply instead of gMultiply and uses invMixMatrix rather than mixMatrix.*/
    short[] result = {0, 0, 0, 0};
    for (int i = 0; i < 4; i++){
      short currentSum = 0;
      for (int j = 0; j < 4; j++){
        short intermediate = InvGMultiply(stateMatrix[j][stateColumn], invMixMatrix[i][j]);
        currentSum = new Integer((new Integer(intermediate).shortValue()) ^ (new Integer(currentSum).shortValue())).shortValue();
      }
      result[i] = currentSum;
    }
    for (int i = 0; i < 4; i++) {
      stateMatrix[i][stateColumn] = result[i];     //put the result into the stateMatrix in column stateColumn
    }
  }

  /**
   * Multiplies a value by a factor 9, 11, 13 or 14 over GF(2^8)
   *
   * @param value the value we are multiplying
   * @param the factor by which we multiply (must be 9, 11, 13 or 14) Returns value if the factor is not valid.
   * @return the product of value*factor over GF(2^8) as a short
   */
  private short InvGMultiply(short value, int factor) {
    if (factor == 2) {
      byte set = new Integer((0x80 & value)>>7).byteValue(); //takes the high bit value

      value = new Integer((value << 1) & 0xff ).shortValue(); //shift the value left by one
      if (set == 1) {
        value = new Integer(value ^ 0x1b).shortValue();
      }
      return value;
    }
    else if (factor == 9) {
      value = new Integer(InvGMultiply(InvGMultiply(InvGMultiply(value, 2), 2), 2) ^ value).shortValue();

      return value;
    }
    else if (factor == 11) {
      value = new Integer(InvGMultiply(new Integer(InvGMultiply(InvGMultiply(value, 2), 2)^value).shortValue(), 2)^value).shortValue();
      return value;
    }
    else if (factor == 13) {
      value = new Integer(InvGMultiply(InvGMultiply(new Integer(InvGMultiply(value, 2)^value).shortValue(), 2), 2)^value).shortValue();
      return value;
    }
    else if (factor == 14) {
      value = InvGMultiply(new Integer(InvGMultiply(new Integer(InvGMultiply(value, 2)^value).shortValue(), 2)^value).shortValue(), 2);
      return value;
    }
    else{
      System.out.println("You did something wrong.!");
      return value;}
  }

  /**
   * Tests AESDecrypter using the Rijndael inspector example and the AES Powerpoint
   * example.
   */
  public static void main(String[] args) {
    //Rijndael inspector test case
    short[][] sampleKey1 ={{0x2b, 0x28, 0xab, 0x09}, {0x7e, 0xae, 0xf7, 0xcf}, {0x15, 0xd2, 0x15, 0x4f}, {0x16, 0xa6, 0x88, 0x3c}};
    Key k = new Key(sampleKey1);

    short[][] ciphertext1 =
            {{0x39, 0x02, 0xdc, 0x19},
            {0x25, 0xdc, 0x11, 0x6a},
            {0x84, 0x09, 0x85, 0x0b},
            {0x1d, 0xfb, 0x97, 0x32}};
    AESDecrypter test = new AESDecrypter(k);
    System.out.println("Rijndael Inspector Test Case");
    System.out.println("Ciphertext: " + new Key(ciphertext1));
    System.out.println("Plaintext: "+ new Key(test.Decrypt(ciphertext1)));

    System.out.println("\n");
    short[][] sampleKey2 = {{0x54, 0x73, 0x20, 0x67},
                           {0x68, 0x20, 0x4b, 0x20},
                           {0x61, 0x6d, 0x75, 0x46},
                           {0x74, 0x79, 0x6e, 0x75}};
    Key k2 = new Key(sampleKey2);
    short[][] ciphertext2 = {{0x29, 0x57, 0x40, 0x1a},{0xc3, 0x14, 0x22, 0x02}, {0x50, 0x20, 0x99, 0xd7}, {0x5f, 0xf6, 0xb3, 0x3a}};
     System.out.println("AES Example Powerpoint Test Case"); //https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
    AESDecrypter test2 = new AESDecrypter(k2);
    System.out.println("Ciphertext: " + new Key(ciphertext2));
    System.out.println("Plaintext: " + new Key(test2.Decrypt(ciphertext2)));
  }
}
