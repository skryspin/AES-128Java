import java.io.*;
import java.lang.Integer;
import java.util.Scanner;
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
public class DecryptTool {

  /**
   * Decrypts the specified file using AES, and saves the decryption to baseName
   *  + "_decrypted.txt"
   *
   * @param filename the name of the file to be decrypted, or the path if
   * the file is not in the current directory
   * @param keyname the name of the file containing the key, formatted as 16 hex bytes separated by spaces.
   * @throws FileNotFoundException if a file is not found
   * @throws IOException if an I/O error occurs
   */
  public static void decryptFile(String filename, String keyname) throws FileNotFoundException, IOException{
    //Reads the ciphertext file
    File ciphertext = new File(filename);
    Scanner ciphertextReader = new Scanner(ciphertext);
    short[][] ciphertextArray = new short[4][4];
    System.out.println("Reading " + filename);
    int i = 0; //the key is inputted by vertically reading it
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++) {
        ciphertextArray[r][c] = Short.parseShort(ciphertextReader.next(), 16);
      }
    }
    ciphertextReader.close();
    System.out.println(new Key(ciphertextArray));

    //Reads the Key file
    File key = new File(keyname);
    Scanner keyReader = new Scanner(key);
    short[][] keyArray = new short[4][4];
    System.out.println("Reading " + keyname + "...  ");
    i = 0; //the key is inputted by vertically reading it
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++) {
        keyArray[r][c] = Short.parseShort(keyReader.next(), 16);
      }
    }
    keyReader.close();

    AESDecrypter test1 = new AESDecrypter(new Key(keyArray));
    short[][] decrypted = test1.Decrypt(ciphertextArray); //Encrypts the message


    //writes the _decrypted file
    String baseName = filename.replace("_encrypted.txt", "");
    BufferedWriter writer = new BufferedWriter(new FileWriter(baseName+"_decrypted.txt"));
    i = 0;
    int[] decryptedBuf = new int[16];
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++) {
        decryptedBuf[i] = decrypted[r][c];
        i++;
      }
    }
    for (i = 0; i < 16; i++) {
      writer.write((char) decryptedBuf[i]);
    }
    writer.close();

    System.out.println("Decrypted " + filename + " to file " + baseName + "_decrypted.txt");
  }

  /**
   *  Decrypts the specified files with a key specified by a provided file,
   * and puts it in filename_decrypted.txt
   *
   * @throws IOException if an I/O error occurs
   */
  public static void main(String[] args) throws IOException{
    try {

      //getting the ciphertext file
      try {
        String file = args[0];

        String key = args[1];

        decryptFile(file,key);
      }
      catch (FileNotFoundException e){
        System.out.println("The specified .txt file could not be found. Please ensure the file is in the current directory, or that path name is correct.");
      }
      catch (NumberFormatException e) {
        System.out.println("The specified encrypted file could not be read. Please ensure that the file contains exactly 16 hex bytes separated by spaces.");
      }

    }
      catch (ArrayIndexOutOfBoundsException e) {
        System.out.println("You must specify both a .txt file to be decrypted and a key file on the command line.");
      }
    }
}
