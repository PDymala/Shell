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

    private PrivateKey privateKey;

    private byte[] fileToEncrypt;
    private Path pathFileToEncrypt;
    private byte[] fileToDecrypt;
    private Path pathFileToDecrypt;
    private PublicKey publicKey;

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


    /**
     * Opens a file chooser dialog to load a public key from a file.
     * The selected file is then processed, and relevant information is displayed on the UI.
     */
    @FXML
    public void loadPublicKey() {
        // Create a file chooser
        FileChooser fileChooser = new FileChooser();

        // Set extension filter for public key files (*.puk)
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("Shell public key", "*.puk");
        fileChooser.getExtensionFilters().add(fileExtension);

        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {
            try {
                // Read the public key from the file
                publicKey = readPublicKeyFromFile(selectedFile.getAbsolutePath());
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                showTextOnLogger("Error while loading the key, try again.");
                throw new RuntimeException(e);
            }

            // Display information about the loaded key on the UI
            showTextOnLogger("Key loaded from file: " + selectedFile.getAbsolutePath());
            textPublicKey.setText("..." + getLastNCharacters(selectedFile.getAbsolutePath(), 20));
        } else {
            showTextOnLogger("No file selected");
        }
    }

    /**
     * Opens a file chooser dialog to load a private key from a file.
     * The selected file is then processed, and relevant information is displayed on the UI.
     */
    @FXML
    public void loadPrivateKey() {
        // Create a file chooser
        FileChooser fileChooser = new FileChooser();

        // Set extension filter for private key files (*.prk)
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("Shell private key", "*.prk");
        fileChooser.getExtensionFilters().add(fileExtension);

        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {
            try {
                // Read the private key from the file
                privateKey = privateKeyFromFile(selectedFile.getAbsolutePath());
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                showTextOnLogger("Error while loading the key, try again.");
                throw new RuntimeException(e);
            }

            // Display information about the loaded key on the UI
            showTextOnLogger("Key loaded from file: " + selectedFile.getAbsolutePath());
            textPrivateKey.setText("..." + getLastNCharacters(selectedFile.getAbsolutePath(), 20));
        } else {
            showTextOnLogger("No file selected");
        }
    }

    /**
     * Opens a file chooser dialog to load a file for encryption.
     * The selected file is then processed, and relevant information is displayed on the UI.
     */
    @FXML
    public void loadFileToEncrypt() {
        // Create a file chooser
        FileChooser fileChooser = new FileChooser();

        // Set extension filter for all files (*.*)
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("File to encrypt", "*.*");
        fileChooser.getExtensionFilters().add(fileExtension);

        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {
            try {
                // Get the path and read the content of the selected file
                pathFileToEncrypt = Path.of(selectedFile.getAbsolutePath());
                fileToEncrypt = readFileFromUrl(selectedFile.getAbsolutePath());
            } catch (IOException e) {
                showTextOnLogger("Error while loading the file, try again.");
                throw new RuntimeException(e);
            }

            // Display information about the loaded file on the UI
            showTextOnLogger("File loaded to encrypt: " + selectedFile.getAbsolutePath());
            textFileToEncrypt.setText(getLastNCharacters(selectedFile.getAbsolutePath(), 15));
        } else {
            showTextOnLogger("No file selected");
        }
    }

    /**
     * Decrypts a file using RSA to decrypt the symmetric key and then AES to decrypt the file content.
     * The decrypted data is then saved to a new file.
     */
    @FXML
    public void decrypt() {
        try {
            // Split the encrypted file content into encrypted symmetric key and encrypted file data
            int keySize = 512;
            byte[] encryptedSymmetricKeyBytesNew = Arrays.copyOfRange(fileToDecrypt, 0, keySize);
            byte[] encryptedDataBytes = Arrays.copyOfRange(fileToDecrypt, keySize, fileToDecrypt.length);

            // Decrypt the symmetric key using RSA
            Cipher rsaDecryptCipher = Cipher.getInstance("RSA");
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
            showTextOnLogger("NoSuchAlgorithmException error");
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException | InvalidKeyException e) {
            showTextOnLogger("NoSuchPaddingException / InvalidKeyException error");
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            showTextOnLogger("FileNotFoundException error");
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            showTextOnLogger("IllegalBlockSizeException error");
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            showTextOnLogger("BadPaddingException error");
            throw new RuntimeException(e);
        } catch (IOException e) {
            showTextOnLogger("IOException error");
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts a file using AES and saves the encrypted data to a new file.
     * The symmetric key used for encryption is then encrypted with RSA and also saved.
     */
    @FXML
    public void encrypt() {
        try {
            // Generate a random AES key
            SecretKey secretKey = generateRandomKeyAES(256);

            // Initialize AES encryption cipher
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
            showTextOnLogger("NoSuchAlgorithmException error");
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException | InvalidKeyException e) {
            showTextOnLogger("NoSuchPaddingException / InvalidKeyException error");
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            showTextOnLogger("FileNotFoundException error");
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            showTextOnLogger("IllegalBlockSizeException error");
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            showTextOnLogger("BadPaddingException error");
            throw new RuntimeException(e);
        } catch (IOException e) {
            showTextOnLogger("IOException error");
            throw new RuntimeException(e);
        }
    }


    /**
     * Opens a file chooser dialog to load a file for decryption.
     * The selected file is then processed, and relevant information is displayed on the UI.
     */
    @FXML
    public void loadFileToDecrypt() {
        // Create a file chooser
        FileChooser fileChooser = new FileChooser();

        // Set extension filter for all files (*.*)
        FileChooser.ExtensionFilter fileExtension = new FileChooser.ExtensionFilter("File to decrypt", "*.*");
        fileChooser.getExtensionFilters().add(fileExtension);

        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(primaryStage);

        // Handle the selected file (you can perform actions with the file here)
        if (selectedFile != null) {
            try {
                // Get the path and read the content of the selected file
                pathFileToDecrypt = Path.of(selectedFile.getAbsolutePath());
                fileToDecrypt = readFileFromUrl(selectedFile.getAbsolutePath());
            } catch (IOException e) {
                showTextOnLogger("Error while loading the file, try again.");
                throw new RuntimeException(e);
            }

            // Display information about the loaded file on the UI
            showTextOnLogger("File loaded to decrypt: " + selectedFile.getAbsolutePath());
            textFileToDecrypt.setText(getLastNCharacters(selectedFile.getAbsolutePath(), 15));
        } else {
            showTextOnLogger("No file selected");
        }
    }


    /**
     * Retrieves the last N characters from the given string.
     *
     * @param originalString the original string
     * @param n              the number of characters to retrieve from the end
     * @return the last N characters of the original string, or the original string if it is null or shorter than N
     */
    private static String getLastNCharacters(String originalString, int n) {
        // Check if the original string is null or shorter than N
        if (originalString == null || originalString.length() <= n) {
            return originalString;
        }
        // Retrieve the last N characters from the original string
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


    /**
     * Generates RSA key pair, saves the public and private keys to files, and logs the results.
     *
     * @throws IOException if an I/O error occurs while saving the keys to files
     */
    @FXML
    protected void generateKeys() throws IOException {
        // Obtain client name from a TextField (assuming textFieldClientName is a field in the controller)
        String clientName = textFieldClientName.getText();

        // Generate RSA key pair with a key size of 4096 bits
        KeyPair keyPair = generateKeyPairRSA(4096);

        // Generate timestamp for creating unique file names
        String timestamp = generateTimeStamp();

        // Define file names for public and private keys
        String publicFileName = timestamp + clientName + "_public.puk";
        String privateFileName = timestamp + clientName + "_private.prk";

        // Save public key to file
        saveKeyToFile(publicFileName, keyPair.getPublic());
        showTextOnLogger("Public key saved to " + publicFileName);

        // Save private key to file
        saveKeyToFile(privateFileName, keyPair.getPrivate());
        showTextOnLogger("Private key saved to " + privateFileName);
    }


    /**
     * Displays formatted text on the logger.
     *
     * @param text the text to be displayed
     */
    private void showTextOnLogger(String text) {
        // Create a Text object with a newline character before the provided text
        Text textFormatted = new Text("\n" + text);

        // Add the formatted text to the TextFlow (assuming textFlowLogger is an instance variable)
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
            showTextOnLogger("Error during key generations, try again");

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
        return dateFormat.format(currentDate)+"_" ;
    }


    /**
     * Generates a random symmetric key for AES encryption.
     *
     * @param keySize the size (in bits) of the generated key, e.g., 128, 192, or 256
     * @return a randomly generated AES key
     * @throws NoSuchAlgorithmException if the specified algorithm (AES) is not available
     */
    private static SecretKey generateRandomKeyAES(int keySize) throws NoSuchAlgorithmException {
        // Generate a random symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize); // Adjust key size as needed
        return keyGenerator.generateKey();
    }

    /**
     * Reads the content of a file from a specified URL and returns it as a byte array.
     *
     * @param filePath the path to the file to be read
     * @return the content of the file as a byte array
     * @throws IOException if an I/O error occurs while reading the file
     */
    private static byte[] readFileFromUrl(String filePath) throws IOException {
        // Path to the original file
        Path originalFilePath = Path.of(filePath);

        // Read the content of the original file into a byte array
        return Files.readAllBytes(originalFilePath);
    }

    /**
     * Reads a private key from a file and returns a {@code PrivateKey} object.
     *
     * @param filePath the path to the private key file
     * @return the {@code PrivateKey} object read from the file
     * @throws IOException              if an I/O error occurs while reading the file
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     * @throws InvalidKeySpecException  if the provided key specification is invalid
     */
    public PrivateKey privateKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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