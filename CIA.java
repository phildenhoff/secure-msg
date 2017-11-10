import static java.nio.charset.StandardCharsets.UTF_8;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.*;
import javax.crypto.*;

public class CIA {
	
	/**
     * This person's public key.
     */	
	private PublicKey pub;
	/**
     * This person's private key.
     */
	private PrivateKey pvt;
	/**
     * The public key of the person they are communicating with.
     */
	private PublicKey theirPublic;
	/**
     * The symmetric key generated for symmetric encryption.
     */
	private SecretKey symmetric;
	
	/**
     * Construct a CIA object.
     * 
	 * @param boolean confidentiality: True if confidentiality selected
	 * @param boolean integrity: True if integrity selected
     * @param boolean authentication: True if authentication selected
     */
	public CIA(boolean confidentiality, boolean integrity, boolean authentication) throws Exception {
		if(confidentiality || integrity){
			generateAsymmetricKeys();
		}
	}
	
	/**
     * Generate a public and private key pair.
     */
	public void generateAsymmetricKeys() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048, new SecureRandom());
		KeyPair pair = keyGen.generateKeyPair();
		pub = pair.getPublic();
		pvt = pair.getPrivate();
	}
	
	/**
     * Generate a symmetric key.
     */
	public void generateSymmetricKey() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128, new SecureRandom());
		symmetric = generator.generateKey();
	}
	
	/**
     * Sets the other persons public key.
	 * 
	 * @param PublicKey theirPub: receives the PublicKey of the other communicator
     */
	public void setTheirPublicKey(PublicKey theirPub) throws Exception {
		theirPublic = theirPub;
	}
	
	/**
     * Sets the symmetric key.
	 * 
	 * @param SecretKey symmetric: the symmetric key to be used for symmetric encryption
     */
	public void setSymmetricKey(SecretKey symmetric){
		this.symmetric = symmetric;
	}
	
	/**
     * Changes the symmetric key into a String
	 * 
	 * @return the symmetric key as a String
     */
	public String secretKeyToString(){
		return Base64.getEncoder().encodeToString(symmetric.getEncoded());
	}
	
	/**
     * Takes the String secretKey and converts it back to a SecretKey object
	 * 
	 * @param String secretKey: the String representation of the symmetric key
     */
	public SecretKey stringToSecretKey(String secretKey){
		byte[] decodedKey = Base64.getDecoder().decode(secretKey);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		symmetric = originalKey;
		return originalKey;
	}
	
	/**
     * Returns the symmetric key.
	 * 
	 * @return the symmetric key
     */
	public SecretKey getSymmetricKey(){
		return symmetric;
	}
	
	/**
     * Returns the public key.
	 * 
	 * @return the public key
     */
	public PublicKey getOurPublicKey(){
		return pub;
	}
	
	/**
     * Returns their public key.
	 * 
	 * @return their public key
     */
	public PublicKey getTheirPublicKey(){
		return theirPublic;
	}
	
	/**
     * Generates and returns a byte array used as an initialization vector for encryption.
	 * 
	 * @return iv for encryption
     */
	public byte[] generateIV(){
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		return iv;
	}
	
	/**
     * Symmetrically encrypts a given message using a given initialization vector. Returns the encrypted message.
	 * 
	 * @param String message: receives the message to be encrypted
	 * @param byte[] iv: receives the initialization vector to be used
	 * @return encrypted message as a String
     */
	public String encryptSymmetric(String message, byte[] iv) throws Exception {
		Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		encryptCipher.init(Cipher.ENCRYPT_MODE, symmetric, new IvParameterSpec(iv));
		byte[] cipherText = encryptCipher.doFinal(message.getBytes(UTF_8));
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	/**
     * Symmetrically decrypts a given encrypted message using a given initialization vector. Returns the decrypted message.
	 * 
	 * @param String message: receives the message to be decrypted
	 * @param byte[] iv: receives the initialization vector to be used
	 * @return decrypted message as a String
     */
	public String decryptSymmetric(String message, byte[] iv) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(message);
		Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		decryptCipher.init(Cipher.DECRYPT_MODE, symmetric, new IvParameterSpec(iv));
		return new String(decryptCipher.doFinal(bytes), UTF_8);
	}
	
	/**
     * Encrypts a given message using the other persons public key. Returns the encrypted message.
	 * 
	 * @param String message: receives the message to be encrypted
	 * @return encrypted message as a String
     */
	public String encryptTheirPublic(String message) throws Exception {
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, theirPublic);
		byte[] cipherText = encryptCipher.doFinal(message.getBytes(UTF_8));
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	/**
     * Decrypts a given message using the private key. Returns the decrypted message.
	 * 
	 * @param String message: receives the message to be decrypted
	 * @return decrypted message as a String
     */
	public String decryptPrivate(String message) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(message);
		Cipher decryptCipher = Cipher.getInstance("RSA");
		decryptCipher.init(Cipher.DECRYPT_MODE, pvt);
		return new String(decryptCipher.doFinal(bytes), UTF_8);
	}
	
	/**
     * Signs a given message using the private key.
	 * 
	 * @param String message: receives the message to be signed
	 * @return signed message as a string
     */
	public String sign(String message) throws Exception {
		Signature privateSign = Signature.getInstance("SHA256withRSA");
		privateSign.initSign(pvt);
		privateSign.update(message.getBytes(UTF_8));
		byte[] signature = privateSign.sign();
		return Base64.getEncoder().encodeToString(signature);
	}
	
	/**
     * Verifies using the other person's public key that the message was signed by them. 
	 * 
	 * @param String message: receives the message that was signed
	 * @param String signature: receives the signature to be verified
	 * @return true if signature matched
     */
	public boolean verifySignature(String message, String signature) throws Exception {
		Signature publicSign = Signature.getInstance("SHA256withRSA");
		publicSign.initVerify(theirPublic);
		publicSign.update(message.getBytes(UTF_8));
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		return publicSign.verify(signatureBytes);	
	}
	
	/**
     * Hashes a given string and returns the hashed result. 
	 * 
	 * @param String message: receives the message to be hashed
	 * @return the hashed message as a String
     */
	public String hashString(String message) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(message.getBytes());
		return new String(messageDigest.digest());
	}
	
	public void testing() throws Exception {
		//Generate asymmetric keys
		generateAsymmetricKeys();
		
		//Test encryptTheirPublic and decryptPrivate methods
		String message = "The answer to life, the universe, and everything";
		String cipherText = encryptTheirPublic(message);
		//System.out.println(cipherText);
		String decryptText = decryptPrivate(cipherText);
		System.out.println(decryptText);
		
		//Test sign and verifySignature methods with plaintext and ciphertext
		String signature = sign(message);
		boolean isCorrect = verifySignature(message, signature);
		System.out.println("Signature correct: " + isCorrect);
		
		//Test sign and verifySignature methods with ciphertext
		String signature2 = sign(cipherText);
		boolean isCorrect2 = verifySignature(cipherText, signature2);
		System.out.println("Signature correct: " + isCorrect2);
		String decryptText2 = decryptPrivate(cipherText);
		System.out.println(decryptText2);
		
		//Generate symmetric key
		generateSymmetricKey();
		
		//Test symmetric encryption and decryption
		String plaintext = "Does this work????";
		byte[] iv = generateIV();
		String ciphertext = encryptSymmetric(plaintext, iv);
		System.out.println(ciphertext);
		String decrypted = decryptSymmetric(ciphertext, iv);
		System.out.println(decrypted);
		
		String hashTest = "Is this hashing a string properly? I dunnnnoooo";
		String hashTest3 = "Do you think this is different?";
		String hash = hashString(hashTest);
		String hash2 = hashString(hashTest);
		String hash3 = hashString(hashTest3);
		String hash4 = hashString(hashTest3);
		System.out.println(hash);
		System.out.println(hash2);
		System.out.println(hash3);
		System.out.println(hash4);
		
		generateSymmetricKey();
		System.out.println(symmetric);
		String symmetricString = secretKeyToString();
		System.out.println(symmetricString);
		SecretKey result = stringToSecretKey(symmetricString);
		System.out.println(result);
	}
	
	public static void main(String[] args) throws Exception {
		CIA cia = new CIA(true, true, true);
		cia.testing();
	}
}