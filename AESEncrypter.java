import java.util.Arrays;


/**
 * AESEncrypter encrypts a 4x4 short array of bytes and prints the resulting ciphertext,
 * as well as each step along the way. You must provide a key with which to encrypt.
 *
 * @see Key
 * @see KeyExpander
 * @see AESDecrypter
 * @author Seb Kryspin
 * @version 1.0
 */

public class AESEncrypter {
  private KeyExpander expand; //key expander
  private short[][] stateMatrix = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}}; //the state matrix

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
  {0x8c,	0xa1,	0x89,	0x0d,	0xbf,	0xe6,	0x42,	0x68, 0x41,	0x99,	0x2d,	0x0f,	0xb0,	0x54,	0xbb,	0x16}}; //S-box for encryption

  private static short[][] mixMatrix = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}}; //the mixMatrix for MixColumns()


  /**
   * Creates an AES Encryption object in preparation for encryption with a given key.
   *
   * @param k the key to use for encryption
   */
  public AESEncrypter(Key k) {
    expand = new KeyExpander(k); //expands the Key
  }

  /**
   * Encrypts a 4x4 short array of bytes using this object's key.
   *
   *
   * It prints every step of encryption.
   *
   * @param plaintext a 4x4 array of bytes, but the bytes are cast as shorts
   * @return a new 4x4 short array containing the ciphertext
   */
  public short[][] Encrypt(short[][] plaintext) {
    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
        stateMatrix[i][j] = plaintext[i][j];
    AddRoundKey(0); //initial round
    System.out.println("AddRoundKey round " + 0);
    printMatrix();
    for (int i = 1; i < 10; i++) { //9 normal rounds
      NormalRoundEncrypt(i);
    }
    FinalRoundEncrypt(); //final round

    short[][] ciphertext = new short[4][4];



    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
        ciphertext[i][j] = stateMatrix[i][j];
        /*This step is EXTREMELY important - we must DEEP COPY the stateMatrix to a
        new array cipherText. If we simply  return stateMatrix, all the variables
        that reference the returned object will refer to the same underlying array.
        This does not cause an issue when encrypting only once, but when encrypting
        multiple blocks with the same key (and thus the same AESEncrypter), as in
        Cipher Block Chaining mode, each encryption will overwrite the previous encryption,
        and thus if we later try to reference, say, an encrypted block i stored in
        some ArrayList of short[][]s, we will receive instead the encryption of the most
        recent block.

        Also: Note that using .clone() or .arrayCopy() will NOT solve this issue,
        since we are using a 2d array which is simply an array of arrays. So, the
        stateMatrix returned would contain a nice NEW array that contains
        references to the same four little arrays in stateMatrix. Thus, the same
        issue as above would result.

        This bug took over 7 hours to solve - take caution.

        Once the issue was found here, the same fix was applied to AESDecrypter.
        */
    return ciphertext;
  }

  /**
   * Performs a normal AES encryption round (not initial or final)
   *
   * @param round the round number, which indicates which key we should use
   */
  private void NormalRoundEncrypt(int round) {
    SubBytes();
    System.out.println("SubBytes round " + round);
    printMatrix();
    ShiftRows();
    System.out.println("Shiftrows round " + round);
    printMatrix();
    MixColumns();
    System.out.println("MixColumns round " + round);
    printMatrix();
    AddRoundKey(round);
    System.out.println("AddRoundKey round " + round);
    printMatrix();
  }

  /**
   * Performs the final round of AES encryption, which does not include MixColumns().
   *
   */
  private void FinalRoundEncrypt() {
    SubBytes();
    System.out.println("SubBytes round " + 10);
    printMatrix();
    ShiftRows();
    System.out.println("Shiftrows round " + 10);
    printMatrix();
    System.out.println("No MixColumns in round 10.");
    AddRoundKey(10);
    System.out.println("AddRoundKey round " + 10);
    printMatrix();
  }

  /**
   * Prints the current state matrix of a AESEncrypter.
   *
   */
  public void printMatrix() {
    for (int row = 0; row < 4; row++) {
      for (int column = 0; column < 4; column++) {
        System.out.print(String.format("%02X", stateMatrix[row][column]) + " ");
      }
      System.out.println();
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
   * Substitutes all bytes in the state matrix using the S-box.
   *
   */
  private void SubBytes() {
    for (int row = 0; row < 4; row++) {
      for (int column = 0; column < 4; column++){
        short value = stateMatrix[row][column];
        stateMatrix[row][column] = sBox[expand.highNibble(value)][expand.lowNibble(value)];
      }
    }
  }

  /**
   * Performs the AES ShiftRows on the stateMatrix.
   *
   * Shifts row 1 left by 1, row 2 left by 2, and row 3 left by 3. Row 0 remains the same.
   *
   */
  private void ShiftRows() {

    //row 1, left shift by 1
    short temp = stateMatrix[1][0];
    for (int column = 0; column < 3; column++) {
      stateMatrix[1][column] = stateMatrix[1][column+1];
    }
    stateMatrix[1][3] = temp;

    //row 2 left shift by 2
    int row = 2;
    short[] old2 = {stateMatrix[row][0], stateMatrix[row][1], stateMatrix[row][2], stateMatrix[row][3]};

    for (int column = 0; column < 4; column++) {
      stateMatrix[row][column] = old2[(column+2)%4];
    }

    //row 3 left shift by 3
    row = 3;
    short[] old3 = {stateMatrix[row][0], stateMatrix[row][1], stateMatrix[row][2], stateMatrix[row][3]};
    for (int column = 0; column < 4; column++) {
      stateMatrix[row][column] = old3[(column+3)%4];
    }
  }


  /**
   * Performs the MixColumns() step of AES encryption.
   *
   */
  private void MixColumns() {
    for (int c = 0; c < 4; c++) {
      mixColumn(c);
    }
  }


  /**
   * Mixes a single column for MixColumns().
   * @param the column index
   */
  private void mixColumn(int stateColumn) {
    short[] result = {0, 0, 0, 0};
    for (int i = 0; i < 4; i++){
      short currentSum = 0;
      for (int j = 0; j < 4; j++){
        short intermediate = gMultiply(stateMatrix[j][stateColumn], mixMatrix[i][j]);
        currentSum = new Integer((new Integer(intermediate).shortValue()) ^ (new Integer(currentSum).shortValue())).shortValue();
      }
      result[i] = currentSum;
    }
    for (int i = 0; i < 4; i++) {
      stateMatrix[i][stateColumn] = result[i];     //put the result into the stateMatrix in column stateColumn
    }
  }

  /**
   * Multiplies a value by a factor 1, 2, or 3 over GF(2^8)
   *
   * @param value the value we are multiplying
   * @param the factor by which we multiply (must be 1, 2, or 3) Returns 0 if the factor is not valid.
   * @return the product of value * factor over G(2^8)
   */
  private short gMultiply(short value, int factor) {
    if (factor == 1) {
      return value;
    }
    else if (factor == 2) {
      byte set = new Integer((0x80 & value)>>7).byteValue(); //takes the high bit value

      value = new Integer((value << 1) & 0xff ).shortValue(); //shift the value left by one
      if (set == 1) {
        value = new Integer(value ^ 0x1b).shortValue();
      }
      return value;
    }
    else if (factor == 3) {
      value = new Integer(value ^ gMultiply(value, new Integer(2).byteValue())).shortValue();
      return value;
    }
    else
      {System.out.println("SOMETHING WENT WRONG with gMultiply");
        return 0;} //You messed up.

  }


/**
 * Tests AESEncrypter using the Rijndael and AES Powerpoint examples, and prints
 * each step.
 */
public static void main(String[] args) {
  short[][] sampleKey1 ={{0x2b, 0x28, 0xab, 0x09}, {0x7e, 0xae, 0xf7, 0xcf}, {0x15, 0xd2, 0x15, 0x4f}, {0x16, 0xa6, 0x88, 0x3c}};
  Key k = new Key(sampleKey1);
  short[][] message = {{0x32, 0x88, 0x31, 0xe0}, {0x43, 0x5a, 0x31, 0x37}, {0xf6, 0x30, 0x98, 0x07}, {0xa8, 0x8d, 0xa2, 0x34}};
  AESEncrypter test = new AESEncrypter(k);
  System.out.println("Rijndael Inspector Test Case"); //http://www.formaestudio.com/rijndaelinspector/archivos/rijndaelanimation.html
  System.out.println("Plaintext: " + new Key(message));
  System.out.println("Ciphertext: "+ new Key(test.Encrypt(message)));

  System.out.println("\n");
  short[][] sampleKey2 ={{0x54, 0x73, 0x20, 0x67},
                         {0x68, 0x20, 0x4b, 0x20},
                         {0x61, 0x6d, 0x75, 0x46},
                         {0x74, 0x79, 0x6e, 0x75}};
  Key k2 = new Key(sampleKey2);
  short[][] message2 ={{0x54, 0x4f, 0x4e, 0x20},
                         {0x77, 0x6e, 0x69, 0x54},
                         {0x6f, 0x65, 0x6e, 0x77},
                         {0x20, 0x20, 0x65, 0x6f}};
  AESEncrypter test2 = new AESEncrypter(k2);
  System.out.println("AES Example Powerpoint Test Case"); //https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
  System.out.println("Plaintext: " + new Key(message2));
  System.out.println("Ciphertext: " + new Key(test2.Encrypt(message2)));
  }
}
