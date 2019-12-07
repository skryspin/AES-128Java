README for AES Implementation
skryspin
11/15/18

Welcome to my AES Implementation! Read on to learn how to encrypt and decrypt
files with this download.

NOTE: We recommend you save this download in a new directory so that none of your
own files could be overwritten.

-------------------------------------------------------------------------------
OVERVIEW
-------------------------------------------------------------------------------

This download contains the following java files, in order of recommended inspection.

Key - a class for creation and printing of Keys
KeyExpander - a class to generate and store the 10 additional "round keys"
needed for AES encryption
AESEncrypter - a class to perform AES encryption with a specified key
AESDecrypter - a class to perform AES decryption with a specified key
EncryptTool - a class to encrypt a file of exactly 16 ASCII characters
DecryptTool - a class to decrypt a file of exactly 16 hex bytes
CBCEncryptTool - a class to encrypt a file of up to 1600 ASCII characters
CBCDecryptTool - a class to decrypt a file of up to 1600 hex bytes

This download contains the following sample files:

dummy.txt - a file containing the text "Two One Nine Two"
dummy_key.txt - a file containing a sample key
1984.txt - a file containing the first couple of paragraphs of 1984 by George Orwell

-------------------------------------------------------------------------------
COMPILATION
-------------------------------------------------------------------------------

Open the terminal and navigate to directory to which you downloaded these files.
Run the following command.
  > javac *.java

You've compiled the files! If one or more files do not compile, please contact
sarah.kryspin@trincoll.edu for help.

-------------------------------------------------------------------------------
OVERVIEW of EXECUTABLES
-------------------------------------------------------------------------------

There are multiple files that can be run for testing purposes. NOTE: From now on
we will refer to the "Rijndael AES Inspector"[1] and "AES.pdf" [2]
collectively as the "sample sources." These sources were referenced heavily for
the testing of this program.

The following files may be executed:

KeyExpander will print each round key of the two sample sources, to show that
it works correctly.

AESEncrypter prints the encryption process for the sample sources.

AESDecrypter prints the decryption process for the sample sources.

EncryptTool will print the encryption process for a provided file "filename.txt"
and save the encryption to "filename_encrypted.txt". If a key file was provided,
it will NOT create a new key file. If a key file was not provided, it will save
the generated key in "filename_key.txt." NOTE: Only encrypts first 16 letters

DecryptTool will print the decryption process for a provided file "filename.txt"
using a provided key file and save the decryption to "filename_decrypted.txt".
NOTE: Only decrypts first 16 hex bytes

CBCEncryptTool will print the encryption process for a provided file "filename.txt"
and save the encryption to "filename_encrypted.txt". If a key file was provided,
it will NOT create a new key file. If a key file was not provided, it will save
the generated key in "filename_key.txt." NOTE: Only encrypts first 1600 ASCII characters.

CBCDecryptTool will print the decryption process for a provided file "filename.txt"
using a provided key file and save the decryption to "filename_decrypted.txt".
NOTE: Only decrypts first 1600 hex bytes

-------------------------------------------------------------------------------
RUNNING INSTRUCTIONS
-------------------------------------------------------------------------------

To run the KeyExpander, do the following:
> java KeyExpander

To run AESEncrypter:
>java AESEncrypter

To run AESDecrypter:
>java AESDecrypter

To run EncryptTool, you must have a text file consisting of 16 ASCII characters.
You may also have a file of 16 hex bytes, separated by spaces, with no prefixes
to use as the key. If you do not provide a key file, a random key will be generated
and saved in a file as "filename_key.txt". For example, if the file is called
"sample.txt" the key will be saved in "sample_key.txt" and the encryption
will be saved in "sample_encrypted.txt"

>java EncryptTool dummy.txt
Or
>java EncryptTool dummy.txt dummy_key.txt

To run DecryptTool, you must have a text file consisting of 16 hex bytes and a key
file consisting of 16 hex bytes. If the text file is called "sample_encrypted.txt"
the decryption will be saved in "sample_decrypted.txt".

>java DecryptTool dummy_encrypted.txt dummy_key.txt

To run CBCEncryptTool, you must have a text file of up to 1600 ASCII characters
(although if there are more it will simply ignore them). You may optionally
provide a key. If you do not provide a key file, a new file will be generated at
"filename_key.txt". For example, if the file is called "filename.txt" the key
will be saved in "filename_key.txt" and the encryption will be saved in
"filename_encrypted.txt." Additionally, a random initialization vector will be
saved in "filename_IV.txt."

>java CBCEncryptTool 1984.txt
OR
>java CBCEncryptTool 1984.txt sample_key.txt (May use dummy_key.txt or your own key)

NOTE: If you provide your own file to save the key, a new key file
won't be generated, so you must remember the location of the key file so you
can provide it for decryption!

To run CBCDecryptTool, you must have an encrypted file of up to 1600 hex bytes,
a key file of 16 hex bytes, and an IV file of 16 hex bytes. If the encrypted file
is called "sample_encrypted.txt," the decryption will be stored in
"sample_decrypted.txt"

>java CBCEncryptTool 1984_encrypted.txt 1984_key.txt 1984_IV.txt

-------------------------------------------------------------------------------
REFERENCES
-------------------------------------------------------------------------------
[1] E. Zabala. “Rijndael Inspector.” Internet:      http://www.formaestudio.com/rijndaelinspector/archivos/rijndaelanimation.html, 2008 [Nov. 17, 2018]

[2] “AES.pdf.” Internet: https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf, Mar. 2014 [Nov. 17, 2018]

[3] G. Orwell. (1949, June 8). 1984. Internet: http://www.george-orwell.org/1984 [Nov. 17, 2018]
