package app.diplabs.shell;

import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

public class Controller {
    @FXML
    TextField textFieldClientName;

    @FXML
    TextFlow textFlowLogger;

    @FXML
    Text textPublicKey;
    @FXML
    Text textPrivateKey;

    @FXML
    Text textFileToEncrypt;

    @FXML
    Text textFileToDecrypt;

    private Stage primaryStage;

    public void setPrimaryStage(Stage primaryStage) {
        this.primaryStage = primaryStage;
    }

    PublicKey publicKey;
    @FXML
    public void loadPublicKey(){

        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("Shell public key", "*.puk");
        fileChooser.getExtensionFilters().add(fileExtension);
        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {

            // Read public key from file
            try {
                publicKey = readPublicKeyFromFile(selectedFile.getAbsolutePath());
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                showTextOnLogger("Error while loading the key, try again.");
                throw new RuntimeException(e);

            }


            showTextOnLogger("Key loaded from file: " + selectedFile.getAbsolutePath());
            textPublicKey.setText("..."+getLastNCharacters(selectedFile.getAbsolutePath(),20));
        } else {
            showTextOnLogger("No file selected");
        }
    }



    PrivateKey privateKey;
    @FXML
    public void loadPrivateKey(){

        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("Shell private key", "*.prk");
        fileChooser.getExtensionFilters().add(fileExtension);
        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {

            // Read public key from file
            try {
                privateKey = privateKeyFromFile(selectedFile.getAbsolutePath());
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                showTextOnLogger("Error while loading the key, try again.");
                throw new RuntimeException(e);

            }


            showTextOnLogger("Key loaded from file: " + selectedFile.getAbsolutePath());
            textPrivateKey.setText("..."+getLastNCharacters(selectedFile.getAbsolutePath(),20));
        } else {
            showTextOnLogger("No file selected");
        }
    }


    byte[] fileToEncrypt;
    Path pathFileToEncrypt;
    @FXML
    public void loadFileToEncrypt(){

        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("File to encrypt", "*.*");
        fileChooser.getExtensionFilters().add(fileExtension);
        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {
            try {
                pathFileToEncrypt = Path.of(selectedFile.getAbsolutePath());
                fileToEncrypt = readFileFromUrl(selectedFile.getAbsolutePath());
            } catch (IOException e) {
                showTextOnLogger("Error while loading the file, try again.");
                throw new RuntimeException(e);
            }
            showTextOnLogger("File loaded to encrypt: " + selectedFile.getAbsolutePath());
            textFileToEncrypt.setText(getLastNCharacters(selectedFile.getAbsolutePath(),15));
        } else {
            showTextOnLogger("No file selected");
        }
    }

    @FXML
    public void decrypt(){

        try {

                /*
                 This keySize is the RSA key size, not AES. Notice how RSA wants BITS and here we have BYTES.
                 THE RSA encrypts stuff into blocks. Does not matter the data size. First we have to take this block away and decrypt
                 the aes key.
                 */
        // Split the encrypted file content into encrypted symmetric key and encrypted file data
        int keySize = 512;
        byte[] encryptedSymmetricKeyBytesNew = Arrays.copyOfRange(fileToDecrypt, 0, keySize);
        byte[] encryptedDataBytes = Arrays.copyOfRange(fileToDecrypt, keySize, fileToDecrypt.length);

        // Decrypt the symmetric key using RSA
        Cipher rsaDecryptCipher = null;

            rsaDecryptCipher = Cipher.getInstance("RSA");

        rsaDecryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyBytes = rsaDecryptCipher.doFinal(encryptedSymmetricKeyBytesNew);

        // Reconstruct the SecretKey object from the decrypted bytes
        SecretKey secretKeyDecrypted = new SecretKeySpec(decryptedSymmetricKeyBytes, "AES");

        // Decrypt the file content using the symmetric key (AES)
        Cipher decryptCipher = Cipher.getInstance("AES");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeyDecrypted);
        byte[] decryptedFileBytes = decryptCipher.doFinal(encryptedDataBytes);

        // Path to the decrypted file
        Path decryptedFilePath = Path.of("decrypted_" + pathFileToDecrypt.getFileName());

            // Save the decrypted data to the new file
        try (FileOutputStream outputStream = new FileOutputStream(decryptedFilePath.toFile())) {
            outputStream.write(decryptedFileBytes);
        }

            showTextOnLogger("Decryption successful. Decrypted file saved to: " + decryptedFilePath);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @FXML
    public void encrypt(){

        try {
            SecretKey secretKey = generateRandomKeyAES(256);


            Cipher encryptCipher = Cipher.getInstance("AES");
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedFileBytes = encryptCipher.doFinal(fileToEncrypt);

            // Encrypt the symmetric key with RSA
            Cipher rsaEncryptCipher = Cipher.getInstance("RSA");
            rsaEncryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSymmetricKeyBytes = rsaEncryptCipher.doFinal(secretKey.getEncoded());

            // Path to the new encrypted file
            Path encryptedFilePath = Path.of("encrypted_" + pathFileToEncrypt.getFileName());

            // Save the encrypted data and encrypted symmetric key to the new file
            try (FileOutputStream outputStream = new FileOutputStream(encryptedFilePath.toFile())) {
                outputStream.write(encryptedSymmetricKeyBytes);
                outputStream.write(encryptedFileBytes);
            }
            showTextOnLogger("Encryption successful. Encrypted file saved to: " + encryptedFilePath);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }


    byte[] fileToDecrypt;
    Path pathFileToDecrypt;
    @FXML
    public void loadFileToDecrypt(){

        FileChooser fileChooser = new FileChooser();
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("File to decrypt", "*.*");
        fileChooser.getExtensionFilters().add(fileExtension);
        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {

            try {
                pathFileToDecrypt = Path.of(selectedFile.getAbsolutePath());
                fileToDecrypt = readFileFromUrl(selectedFile.getAbsolutePath());
            } catch (IOException e) {
                showTextOnLogger("Error while loading the file, try again.");
                throw new RuntimeException(e);
            }

            showTextOnLogger("File loaded to decrypt: " + selectedFile.getAbsolutePath());
            textFileToDecrypt.setText(getLastNCharacters(selectedFile.getAbsolutePath(),15));
        } else {
            showTextOnLogger("No file selected");
        }
    }


    private static String getLastNCharacters(String originalString, int n) {
        if (originalString == null || originalString.length() <= n) {
            return originalString;
        }
        return originalString.substring(originalString.length() - n);
    }



    /**
     * Reads a public key from a file and returns it.
     *
     * @param filePath The path to the file containing the public key.
     * @return The PublicKey read from the specified file.
     * @throws IOException              If an I/O error occurs while reading the public key from the file.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws InvalidKeySpecException  If the provided key specification is invalid or not supported.
     */
    public PublicKey readPublicKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {



        // Create a File object representing the public key file
        File publicKeyFile = new File(filePath);

        // Read the bytes from the public key file
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        // Get an RSA key factory instance
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Create a key specification from the encoded public key bytes
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        // Generate the PublicKey from the key specification
        PublicKey publicKeyReturned = keyFactory.generatePublic(publicKeySpec);

        return publicKeyReturned;
    }



    @FXML
    protected void generateKeys() throws IOException {
        String clientName = "";
        clientName += textFieldClientName.getText();
        KeyPair keyPair = generateKeyPairRSA(4096);
        String timestamp = generateTimeStamp();

        String publicFileName = timestamp + clientName + "_public.puk";
        String privateFileName = timestamp + clientName + "_private.prk";
        // Save public key to file
        saveKeyToFile(publicFileName, keyPair.getPublic());
        showTextOnLogger("Public key saved to" + publicFileName);

        // Save private key to file
        saveKeyToFile(privateFileName, keyPair.getPrivate());
        showTextOnLogger("Private key saved to" + privateFileName);

    }


    private void showTextOnLogger(String text) {

        // create text
        Text textFormatted = new Text("\n" + text);

        // set the text color
//        text_2.setFill(Color.BLUE);

        // set font of the text
//        text_2.setFont(Font.font("Helvetica", FontPosture.ITALIC, 15));

        // add text to textflow
        textFlowLogger.getChildren().add(textFormatted);


    }


    /**
     * Saves a cryptographic key to a file.
     *
     * @param filePath The path to the file where the key will be saved.
     * @param key      The cryptographic key to be saved.
     * @throws IOException If an I/O error occurs while writing the key to the file.
     */
    private void saveKeyToFile(String filePath, Key key) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            // Write the encoded representation of the key to the file
            fos.write(key.getEncoded());
        }
    }


    /**
     * Generates an RSA key pair and saves the public and private keys to files.
     *
     * @param byteSize The size of the key in bytes.
     * @throws RuntimeException If an IOException or NoSuchAlgorithmException occurs during key pair generation or file saving.
     */
    private KeyPair generateKeyPairRSA(int byteSize) {
        try {

            // Generate RSA key pair
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(byteSize);

            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            // Propagate the exception as a runtime exception
            throw new RuntimeException(e);
        }
    }


    /**
     * Generates a timestamp based on the current date and time in the format "yyyyMMddHHmmss".
     *
     * @return A string representation of the timestamp.
     */
    public static String generateTimeStamp() {
        // Create a date formatter with the specified pattern
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");

        // Get the current date and time
        Date currentDate = new Date();

        // Format the date and time using the specified pattern
        return "_" + dateFormat.format(currentDate);
    }


    private static SecretKey generateRandomKeyAES(int i) throws NoSuchAlgorithmException {

        // Generate a random symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(i); // Adjust key size as needed
        return keyGenerator.generateKey();
    }

    private static byte[] readFileFromUrl(String s) throws IOException {
        // Path to the original file
        Path originalFilePath = Path.of(s);
        // Read the content of the original file into a byte array
        return Files.readAllBytes(originalFilePath);

    }

    public  PrivateKey privateKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Create a File object representing the private key file
        File privateKeyFile = new File(filePath);

        // Read the bytes from the private key file
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());

        // Get an RSA key factory instance
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Create a key specification from the encoded private key bytes
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        // Generate the PrivateKey from the key specification
        PrivateKey privateKeyReturned = keyFactory.generatePrivate(privateKeySpec);

        return privateKeyReturned;
    }

}