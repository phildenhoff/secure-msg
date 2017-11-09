import java.io.Serializable;
import java.security.*;
import javax.crypto.*;
/**
 * Defines a MessagePackage to send to the other system
 */

import javax.crypto.SecretKey;
class MessagePackage implements java.io.Serializable {
    private String msg;
    private String fp;
    private byte[] iv;
    private boolean[] options;
    private PublicKey pubKey;
    private SecretKey symmetricKey;
    private String deviceName;

    /**
     * Construct a MessagePackage.
     * 
     * @param String msg: Message to send
     * @param String fp: fingerprint of message
     */
    public MessagePackage (String msg, String fp) {
        this.msg = msg;
        this.fp = fp;
    }

    /**
     * Construct a MessagePackage.
     * 
     * @param String msg: Message to send
     */
    public MessagePackage (String msg) {
        this.msg = msg;
    }

    /**
     * Returns the message from a MessagePackage
     * 
     * @return message as a String
     */
    public String getMessage () {
        return this.msg;
    }

    /**
     * Returns the fingerprint from a MessagePackage
     * 
     * @return fingerprint as a String
     */
    public String getFingerprint () {
        return this.msg;
    }

	/**
     * Sets initialization options for confidentiality, integrity, and authentication
     * 
     * @param boolean conf: True if confidentiality selected
     * @param boolean integ: True if integrity selected
	 * @param boolean auth: True if authentication selected
     */
    public void setInitOptions (boolean conf, boolean integ, boolean auth) {
        options = new boolean[] {conf, integ, auth};
    }

	/**
     * Returns the boolean array containing selected options for confidentiality, integrity, and authentication
     * 
     * @return options as a boolean array
     */
    public boolean[] getOptions () {
        return options;
    }

	/**
     * Returns the initialization vector used for encryption
     * 
     * @return iv as a byte array
     */
    public byte[] getIV () {
        return iv;
    }

	/**
     * Sets the symmetric key
     */
    public void setSymmSecretKey (SecretKey symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

	/**
     * Returns the symmetric key
     * 
     * @return the symmetric key used as a SecretKey
     */
    public SecretKey getSymmSecretKey () {
       return this.symmetricKey;
    }

	/**
     * Sets the public key
     */
    public void setPublicKey (PublicKey pubKey) {
        this.pubKey = pubKey;
    }

	/**
     * Returns the fingerprint from a MessagePackage
     * 
     * @return pubKey as a public key
     */
    public PublicKey getPublicKey () {
       return this.pubKey;
    }

	/**
     * Sets the device name
     */
    public void setDeviceName (String deviceName) {
        this.deviceName = deviceName;
    }

	/**
     * Returns the device name
     * 
     * @return deviceName as String
     */
    public String getDeviceName () {
        return this.deviceName;
    }

}