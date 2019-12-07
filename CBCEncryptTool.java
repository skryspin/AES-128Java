import java.io.*;
import java.lang.Integer;
import java.util.Scanner;
import java.util.ArrayList;
//https://www.geeksforgeeks.org/different-ways-reading-text-file-java/
//https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html


/**
 * Encrypts a character .txt file up to 1600 characters with AES and saves its encryption to a new
 * file in the same directory as the original file, with the original name + _encrypted.txt.
 *
 * You can use a file in any directory as long as the path is correct.
 *
 *
 * @see AESEncrypter
 * @see EncryptTool
 * @author Seb Kryspin
 * @version 1.0
 */
public class CBCEncryptTool {


  /**
   * Encrypts the specified file using AES with a specified key from a file, and returns
   * the name of the encrypted file.
   *
   * @param filename the name of the file to be encrypted, or the path if
   * the file is not in the current directory
   * @param keyname the name of the file containing the key, formatted as 16 hex bytes separated by spaces.
   * The file must contain a sequence of 16 hex bytes without prefixes. Values must be separated by spaces.
   * @return the base file name
   * @throws FileNotFoundException if filename or keyname file is not found
   * @throws IOException if a file was improperly formatted
   */
  public static String encryptFile(String filename, String keyname) throws FileNotFoundException, IOException{
    ArrayList<short[][]> message = readMessageFile(filename);           //Reads the Message file

    short[][] keyArray = readKeyFile(keyname);                //Reads the Key file

    AESEncrypter aes = new AESEncrypter(new Key(keyArray)); //Creates a new AESEncrypter with the specified key
    int n = message.size();

    ArrayList<short[][]> encrypted = new ArrayList<short[][]>(n);
    short[][] prev = writeIVToFile(filename); //generates an IV and writes it;

    for (int i = 0; i < n; i++){
      short[][] plaintext = message.get(i);
      prev = aes.Encrypt(XOR(prev, plaintext)); //uses the previous block's encryption and XORS it with the plaintext
      encrypted.add(i, prev); //adds the array to the list of blocks

    }
    System.out.println("# of Blocks: " + encrypted.size());
    writeEncryptedToFile(filename, encrypted);                  //writes the _encrypted file
    return filename; //returns the base filename

  }

  /**
   * Encrypts the specified file using AES and a random key, and returns
   * the name of the encrypted file. Stores random key in filename + "_key.txt"
   *
   * @param filename the base name of the file to be encrypted, or the path if
   * the file is not in the current directory
   * @return the base file name
   * @throws FileNotFoundException if filename is not found
   */
  public static String encryptFile(String filename) throws FileNotFoundException, IOException{
    ArrayList<short[][]> message = readMessageFile(filename);           //Reads the Message file
    Key randomKey = new Key();
    writeKeyToFile(filename, randomKey.getKeyValue());
    AESEncrypter aes = new AESEncrypter(randomKey); //Creates a new AESEncrypter with the specified key
    int n = message.size();

    //CBC Encryption with iVector, message, and aes
    ArrayList<short[][]> encrypted = new ArrayList<short[][]>(n);
    short[][] prev = writeIVToFile(filename); //generates an IV and writes it

    for (int i = 0; i < n; i++){
      short[][] plaintext = message.get(i);
      prev = aes.Encrypt(XOR(prev, plaintext)); //uses the previous block's encryption and XORS it with the plaintext
      encrypted.add(i, prev); //adds the array to the list of blocks
    }
    System.out.println("# of Blocks: " + encrypted.size());
    writeEncryptedToFile(filename, encrypted);

    return filename;
  }

  /**
   * Returns the XOR of two 4x4 short arrays.
   *
   * @param one a 4x4 short array
   * @param two a 4x4 short array
   * @return a 4x4 short array where each result[i][j] = one[i][j] ^ two[i][j]
   */
  private static short[][] XOR(short[][] one, short[][] two) {
    short[][] result = new short[4][4];
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++){
        result[r][c] = (new Integer(one[r][c] ^ two[r][c])).shortValue(); //XOR array 1 with array 2
      }
    }
    return result;
  }


  /**
   * Reads a message file of up to 1600 ASCII characters, and returns the message in an ArrayList
   * of 4x4 arrays of shorts.
   *
   * @param filename the file to read from
   * @return the message in an arrayList of 4x4 arrays of shorts
   * @throws FileNotFoundException
   * @throws IOException
   */
  private static ArrayList<short[][]> readMessageFile(String filename) throws FileNotFoundException, IOException{
    File fileOne = new File(filename + ".txt");
    BufferedReader reader = new BufferedReader(new FileReader(fileOne));
    ArrayList<short[][]> message = new ArrayList<short[][]>();

    short[][] block;
    int count = 0; //make sure we don't keep reading forever
    while (reader.ready() && count < 100) {
      block = new short[4][4];
      for (int c = 0; c < 4; c++){
        for (int r = 0; r < 4; r++){
          if (reader.ready()) {
            block[r][c] = (short) reader.read();
          }
          else {
            block[r][c] = 0; //padding
          }
        }
      }
      message.add(count, block);
      count = count + 1; //increment block count
    }
    System.out.println("Reading " + filename + ".txt...  ");
    reader.close();
    return message;
  }


  /**
   * Reads a key file of 16 hex bytes as Strings separated by spaces, and returns the key in a 4x4 array.
   *
   * @param keyname the file to read from
   * @return the key in a 4x4 array of shorts
   * @throws FileNotFoundException
   * @throws IOException
   */
    private static short[][] readKeyFile(String keyname) throws FileNotFoundException, IOException {
      File key = new File(keyname + ".txt");
      Scanner keyReader = new Scanner(key);
      short[][] keyArray = new short[4][4];
      System.out.println("Reading " + keyname + ".txt...  ");
      int i = 0; //the key is inputted by vertically reading it
      for (int c = 0; c < 4; c++){
        for (int r = 0; r < 4; r++) {
          keyArray[r][c] = Short.parseShort(keyReader.next(), 16);
        }
      }
      keyReader.close();
      return keyArray;
    }


  /**
   * Writes an IV for cipherblock chaining for a specified file
   *
   * @param the base file name we will add "_IV.txt" to
   * @return the IV that was generated as a 4x4 short array
   * @throws FileNotFoundException
   * @throws IOException
   */
  private static short[][] writeIVToFile(String filename) throws FileNotFoundException, IOException{
    short[][] keyValue = (new Key()).getKeyValue(); //makes a random IV to save
    BufferedWriter writer = new BufferedWriter(new FileWriter(filename+"_IV.txt"));
    int i = 0;
    int[] keyBuf = new int[16];
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++) {
        keyBuf[i] = keyValue[r][c];
        i++;
      }
    }
    for (i = 0; i < 16; i++) {
      writer.write(String.format("%02X", keyBuf[i]), 0, 2);
      writer.write(' ');
    }
    writer.close();
    System.out.println("Saved randomly generated IV in " + filename+"_IV.txt");
    return keyValue;
  }

  /**
   * Writes a 2d array of shorts containing key values to filename + "_key.txt"
   * as hex bytes separated by spaces.
   *
   * @param filename the base name of the file to write to
   * @param array the 2d short array to read from
   * @throws FileNotFoundException
   * @throws IOException
   */
  private static void writeKeyToFile(String filename, short[][] keyValue) throws FileNotFoundException, IOException {
    BufferedWriter writer = new BufferedWriter(new FileWriter(filename+"_key.txt"));
    int i = 0;
    int[] keyBuf = new int[16];
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++) {
        keyBuf[i] = keyValue[r][c];
        i++;
      }
    }
    for (i = 0; i < 16; i++) {
      writer.write(String.format("%02X", keyBuf[i]), 0, 2);
      writer.write(' ');
    }
    writer.close();
    System.out.println("Saved randomly generated key in " + filename+"_key.txt");
  }

  /**
   * Writes a 2d array of shorts containing encrypted values to filename + "_encrypted.txt"
   * as hex bytes separated by spaces.
   *
   * @param filename the base name of the file to write to
   * @param encrypted the ArrayList of short[][]s to read from
   * @throws FileNotFoundException
   * @throws IOException
   */
  private static void writeEncryptedToFile(String filename, ArrayList<short[][]> encrypted) throws FileNotFoundException, IOException {
    File fileOne = new File(filename + "_encrypted.txt");
    BufferedWriter writer = new BufferedWriter(new FileWriter(fileOne));
    int n = encrypted.size();

    for (int i = 0; i < n; i++) {
      for (int c = 0; c < 4; c++){
        for (int r = 0; r < 4; r++){
          writer.write(String.format("%02X", encrypted.get(i)[r][c]));
          writer.write(' ');
        }
      }
    }

    System.out.println("Writing to " + filename + "_encrypted.txt...  ");
    writer.close();
  }


  /**
   * Encrypts a file from the command line with a key from a file, or uses a
   * random key if no key file is provided.
   *
   * @param args an array containing the plaintext filename at 0 and, optionally, the key
   * filename at 1.
   * @throws FileNotFoundException if one of the files is not found
   * @throws IOException if an I/O error occurs
   */
  public static void main(String[] args) throws FileNotFoundException, IOException{
    try {
      //getting the plaintext message file
      try {
        String file = args[0];
        file  = file.replace(".txt", "");

        try {
          String key = args[1];
          key = key.replace(".txt", "");

          encryptFile(file,key);
        }
        catch (ArrayIndexOutOfBoundsException e) {
          System.out.println("Since no key file was provided, we will encrypt with a random key, which we store in" + file+ "_key.txt in the same directory as the plaintext.");
          encryptFile(file);
        }
      }
      catch (FileNotFoundException e){
        System.out.println("The specified .txt file could not be found. Please ensure the file is in the current directory, or that path name is correct.");
      }

    }
      catch (ArrayIndexOutOfBoundsException e) {
        System.out.println("You must specify a .txt file to be encrypted. You may also specify a key file to use.");
      }
    }
}