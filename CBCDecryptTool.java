import java.io.*;
import java.lang.Integer;
import java.util.Scanner;
import java.util.ArrayList;

//https://www.geeksforgeeks.org/different-ways-reading-text-file-java/
//https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html


/**
 * Decrypts a 16 hex string .txt file using a key
 * from the specified files and saves its decryption to a new file in the same
 * directory as the original file as filename + "_decrypted.txt".
 *
 * You can use a file in any directory as long as the path is correct.
 *
 *
 * @see AESDecrypter
 * @see EncryptTool
 * @author Seb Kryspin
 * @version 1.0
 */
public class CBCDecryptTool {

  /**
   * Decrypts the specified file using AES, and saves the decryption to basename
   *  + "_decrypted.txt"
   *
   * @param filename the name of the file to be decrypted, or the path if
   * the file is not in the current directory
   * @param keyname the name of the file containing the key, formatted as 16 hex bytes separated by spaces.
   * @param iVectorFileName the name of the file containing the initialization vector, or IV
   * @throws FileNotFoundException if one of the files is not found
   * @throws IOException if an I/O error occurs
   */
  public static void decryptFile(String filename, String keyname, String iVectorFileName) throws FileNotFoundException, IOException{

    ArrayList<short[][]> ciphertext = readCiphertextFile(filename);           //Reads the ciphertext file

    short[][] keyArray = readKeyorIVFile(keyname);     //Reads the Key file
    short[][] iVector = readKeyorIVFile(iVectorFileName);  //reads the IV file


    AESDecrypter aes = new AESDecrypter(new Key(keyArray));
    int n = ciphertext.size();

    ArrayList<short[][]> decrypted = new ArrayList<short[][]>(n);

    //cbc mode decryption
    short[][] previous = iVector;
    short[][] untouchedBlock = new short[4][4];
    short[][] newBlock = new short[4][4];


    for (int i = 0; i < n; i++){
      untouchedBlock = ciphertext.get(i); //an untouched block of ciphertext
      newBlock = XOR(aes.Decrypt(untouchedBlock), previous); //a fully decrypted block of ciphertext
      previous = untouchedBlock;
      decrypted.add(i, newBlock);            //Encrypts the message
    }


    String writename = filename.replace("_encrypted.txt", "_decrypted.txt");


    writeDecryptedToFile(writename, decrypted);

    System.out.println("Decrypted " + filename + " to file " + writename);
  }

  /**
   * Returns the XOR of two 4x4 short arrays.
   *
   * @param one a short[4][4] array
   * @param two a short[4][4] array
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
   * Reads a ciphertext file of up to 1600 hex byte strings, and returns the text in a 4x4 array.
   *
   * @param filename the file to read from
   * @return the ciphertext in an ArrayList of 4x4 array of shorts
   * @throws FileNotFoundException if a file could not be found
   * @throws IOException if an I/O exception occurs
   */
  private static ArrayList<short[][]> readCiphertextFile(String filename) throws FileNotFoundException, IOException{
    try {
      File fileOne = new File(filename);
      Scanner reader = new Scanner(fileOne);
      ArrayList<short[][]> ciphertext = new ArrayList<short[][]>();

      int count = 0; //make sure we don't keep reading forever
      while (reader.hasNext() && count < 100) {
        short[][] block = new short[4][4];
        for (int c = 0; c < 4; c++){
          for (int r = 0; r < 4; r++){
            block[r][c] = Short.parseShort(reader.next(), 16);
          }
        }
        ciphertext.add(count, block);
        count = count + 1; //increment block count
      }
      System.out.println("Reading " + filename + "...  ");
      reader.close();
      return ciphertext;
    }
    catch (NumberFormatException e) {
      throw new NumberFormatException("File " + filename + " could not be read as a ciphertext. Please ensure the ciphertext is properly formatted.");
    }
  }

  /**
   * Returns a short[4][4] representation of a key or IV file, which contain 16 hex byte
   * values separated by spaces.
   *
   * @param filename the full name of the file to read
   * @return the key or IV as a 4x4 short
   * @throws FileNotFoundException if the file filename is not found
   */
  public static short[][] readKeyorIVFile(String filename) throws FileNotFoundException{
    try {
      File key = new File(filename);
      Scanner keyReader = new Scanner(key);
      short[][] keyArray = new short[4][4];
      System.out.println("Reading " + filename + "...  ");
      int i = 0; //the key is inputted by vertically reading it
      for (int c = 0; c < 4; c++){
        for (int r = 0; r < 4; r++) {
          keyArray[r][c] = Short.parseShort(keyReader.next(), 16);
        }
      }
      keyReader.close();
      return keyArray;
    }
    catch (NumberFormatException e) {
      throw new NumberFormatException("File " + filename + "is not a file consisting of 16 hex bytes without prefixes, so it could not be read. Please ensure it is properly formatted.");
    }
  }

  /**
   * Writes an ArrayList of 4x4 short arrays containing decrypted values to filename + "_decrypted.txt" as characters
   *
   * @param filename the full name of the file to write to
   * @param encrypted the ArrayList of short[][]s to read from
   */
  private static void writeDecryptedToFile(String filename, ArrayList<short[][]> decrypted) throws FileNotFoundException, IOException {
    File fileOne = new File(filename);
    BufferedWriter writer = new BufferedWriter(new FileWriter(fileOne));
    int n = decrypted.size();
    System.out.println("# Of Blocks: " + decrypted.size());

    for (int i = 0; i < n; i++) {
      for (int c = 0; c < 4; c++){
        for (int r = 0; r < 4; r++){
          writer.write((char) decrypted.get(i)[r][c]);
        }
      }
    }
    writer.close();
  }


  /**
   * Decrypts a file using the specified key and IV files.
   *
   * @param args args[0] is the ciphertext file, args[1] is the key file, and args[2] is the IV file
   * @throws IOException if an I/O error occurs
   */
  public static void main(String[] args) throws IOException{
    try {
      try {
        String file = args[0];

        String key = args[1];

        String iVector = args[2];

        decryptFile(file,key,iVector);
      }
      catch (FileNotFoundException e){
        System.out.println("The specified .txt file could not be found. Please ensure the file is in the current directory, or that path name is correct.");
      }
    }
    catch (ArrayIndexOutOfBoundsException e) {
      System.out.println("You must specify  a .txt file to be encrypted, a key file, and an IV file on the command line.");
    }
    catch (NumberFormatException e) {
      System.out.println(e.getMessage());
    }
  }
}
