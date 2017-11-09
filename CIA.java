import static java.nio.charset.StandardCharsets.UTF_8;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.*;
import javax.crypto.*;

class CIA {
		
	private PublicKey pub;
	private PrivateKey pvt;
	private PublicKey theirPublic;
	private SecretKey symmetric;
	
	public CIA(boolean confidentiality, boolean integrity, boolean authentication) throws Exception {
		if(confidentiality){
			generateAsymmetricKeys();
			generateSymmetricKey();
		}
		if(integrity){
			if(pub != null && pvt != null){
				generateAsymmetricKeys();
			}
		}
	}
	
	public void generateAsymmetricKeys() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048, new SecureRandom());
		KeyPair pair = keyGen.generateKeyPair();
		pub = pair.getPublic();
		pvt = pair.getPrivate();
	}
	
	public void generateSymmetricKey() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128, new SecureRandom());
		symmetric = generator.generateKey();
	}
	
	public void setTheirPublicKey(PublicKey theirPub) throws Exception {
		theirPublic = theirPub;
	}
	
	public SecretKey getSymmetricKey(){
		return symmetric;
	}
	
	public PublicKey getOurPublicKey(){
		return pub;
	}
	
	public byte[] generateIV(){
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		return iv;
	}
	
	public String encryptSymmetric(String message, byte[] iv) throws Exception {
		Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		encryptCipher.init(Cipher.ENCRYPT_MODE, symmetric, new IvParameterSpec(iv));
		byte[] cipherText = encryptCipher.doFinal(message.getBytes(UTF_8));
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	public String decryptSymmetric(String message, byte[] iv) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(message);
		Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		decryptCipher.init(Cipher.DECRYPT_MODE, symmetric, new IvParameterSpec(iv));
		return new String(decryptCipher.doFinal(bytes), UTF_8);
	}
	
	//NOTE: need to change all pub instances to theirPublic
	public String encryptTheirPublic(String message) throws Exception {
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, pub);
		byte[] cipherText = encryptCipher.doFinal(message.getBytes(UTF_8));
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	public String decryptPrivate(String message) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(message);
		Cipher decryptCipher = Cipher.getInstance("RSA");
		decryptCipher.init(Cipher.DECRYPT_MODE, pvt);
		return new String(decryptCipher.doFinal(bytes), UTF_8);
	}
	
	public String sign(String message) throws Exception {
		Signature privateSign = Signature.getInstance("SHA256withRSA");
		privateSign.initSign(pvt);
		privateSign.update(message.getBytes(UTF_8));
		byte[] signature = privateSign.sign();
		return Base64.getEncoder().encodeToString(signature);
	}
	
	//NOTE: need to change all pub instances to theirPublic
	public boolean verifySignature(String message, String signature) throws Exception {
		Signature publicSign = Signature.getInstance("SHA256withRSA");
		publicSign.initVerify(pub);
		publicSign.update(message.getBytes(UTF_8));
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		return publicSign.verify(signatureBytes);	
	}
	
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
	}
	
	public static void main(String[] args) throws Exception {
		CIA cia = new CIA(true, true, true);
		cia.testing();
	}
}