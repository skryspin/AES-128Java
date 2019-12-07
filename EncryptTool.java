import java.io.*;
import java.lang.Integer;
import java.util.Scanner;
//https://www.geeksforgeeks.org/different-ways-reading-text-file-java/
//https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html


/**
 * Encrypts a 16 character .txt file with AES and saves its encryption to a new
 * file in the same directory as the original file, with the original name + _encrypted.txt.
 *
 * You can use a file in any directory as long as the path is correct.
 *
 *
 * @see AESEncrypter
 * @see DecryptTool
 * @author Seb Kryspin
 * @version 1.0
 */
public class EncryptTool {

  /**
   * Encrypts the specified file filename.txt using AES with a specified key from a file.
   *
   * @param filename the name of the file to be encrypted, or the path if
   * the file is not in the current directory
   * @param keyname the name of the file containing the key, formatted as 16 hex bytes separated by spaces.
   * The file must contain a sequence of 16 hex bytes without prefixes. Values must be separated by spaces.
   * @throws FileNotFoundException if filename or keyname is not found
   * @throws IOException if filename or keyname are improperly formatted
   */
  public static void encryptFile(String filename, String keyname) throws FileNotFoundException, IOException{
    short[][] message = readMessageFile(filename);           //Reads the Message file
    short[][] keyArray = readKeyFile(keyname);                //Reads the Key file
    AESEncrypter aes = new AESEncrypter(new Key(keyArray)); //Creates a new AESEncrypter with the specified key
    short[][] encrypted = aes.Encrypt(message);            //Encrypts the message
    writeEncryptedToFile(filename, encrypted);                  //writes the _encrypted file
  }

  /**
   * Encrypts the specified file using AES and a random key, and returns
   * the name of the encrypted file. Stores random key in filename + "_key.txt"
   *
   * @param filename the base name of the file to be encrypted, or the path if
   * the file is not in the current directory (i.e, the filename does not include the .txt)
   * @throws FileNotFoundException if filename is not found
   * @throws IOException if an I/O error occurs
   */
  public static void encryptFile(String filename) throws FileNotFoundException, IOException{

    short[][] message = readMessageFile(filename);           //Reads the Message file
    Key randomKey = new Key();

    writeKeyToFile(filename, randomKey.getKeyValue());

    AESEncrypter aes = new AESEncrypter(randomKey); //Creates a new AESEncrypter with the specified key
    short[][] encrypted = aes.Encrypt(message);            //Encrypts the message

    writeEncryptedToFile(filename, encrypted);
  }

  /**
   * Reads a message file of 16 ASCII characters, and returns the message in a 4x4 array.
   *
   * @param filename the file to read from
   * @return the message in a 4x4 array of shorts
   * @throws FileNotFoundException if the filename.txt could not be found
   * @throws IOException if an I/O error occurs
   */
  private static short[][] readMessageFile(String filename) throws FileNotFoundException, IOException{
    File fileOne = new File(filename + ".txt");
    BufferedReader reader = new BufferedReader(new FileReader(fileOne));
    short[][] message1 = new short[4][4];
    char[] cbuf = new char[16];
    reader.read(cbuf, 0, 16);
    System.out.println("Reading " + filename + ".txt...  ");
    reader.close();
    int i = 0; //the message is inputted by vertically reading it
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++)
        { message1[r][c] = (short) cbuf[i];
          i++;}}
    return message1;
  }

  /**
   * Reads a key file of 16 hex bytes as Strings separated by spaces, and returns the key in a 4x4 array.
   *
   * @param keyname the file to read from
   * @return the key in a 4x4 array of shorts
   * @throws FileNotFoundException if the keyname.txt could not be found
   * @throws IOException if an I/O error occurs
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
   * Writes a 2d array of shorts to a specified file as hex bytes separated by spaces.
   *
   * @param filename the exact name of the file to which we will write the array
   * @param array the 2d short array to read from
   * @throws FileNotFoundException if the filename.txt could not be found
   * @throws IOException if an I/O error occurs
   */
  private static void writeToFile(String filename, short[][] array) throws FileNotFoundException, IOException{
    BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
    int i = 0;
    int[] keyBuf = new int[16];
    for (int c = 0; c < 4; c++){
      for (int r = 0; r < 4; r++) {
        keyBuf[i] = array[r][c];
        i++;
      }
    }
    for (i = 0; i < 16; i++) {
      writer.write(String.format("%02X", keyBuf[i]), 0, 2);
      writer.write(' ');
    }
    writer.close();
  }

  /**
   * Writes a 2d array of shorts containing key values to filename + "_key.txt"
   * as hex bytes separated by spaces.
   *
   * @param filename the base name of the file to which we will write the key
   * @param array the 2d short array to read from
   * @throws FileNotFoundException if the filename.txt could not be found
   * @throws IOException if an I/O error occurs
   */
  private static void writeKeyToFile(String filename, short[][] keyValue) throws FileNotFoundException, IOException {
    writeToFile(filename+"_key.txt", keyValue);
    System.out.println("Saved randomly generated key in " + filename+"_key.txt");
  }

  /**
   * Writes a 2d array of shorts containing encrypted values to filename + "_encrypted.txt"
   * as hex bytes separated by spaces.
   *
   * @param filename the base name of the file to which we will write the encrypted message
   * @param array the 2d short array to read from
   * @throws FileNotFoundException if the filename.txt could not be found
   * @throws IOException if an I/O error occurs
   */
  private static void writeEncryptedToFile(String filename, short[][] encrypted) throws FileNotFoundException, IOException {
    writeToFile(filename+"_encrypted.txt", encrypted);
    System.out.println("Encrypted " + filename + ".txt to file " + filename + "_encrypted.txt");
  }

  /**
   * Encrypts the specified files with either a key specified by a provided file
   * or a random key.
   *
   * @throws FileNotFoundException if any file could not be found
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
          System.out.println("Since no key file was provided, we will encrypt with a random key, which we store in " + file+ "_key.txt in the same directory as the plaintext.");
          encryptFile(file);
        }
      }
      catch (FileNotFoundException e){
        System.out.println("One of the specified .txt files could not be found. Please ensure the file is in the current directory, or that path name is correct.");
      }

    }
      catch (ArrayIndexOutOfBoundsException e) {
        System.out.println("You must specify both a .txt file to be encrypted and a key file on the command line.");
      }
    }
}
