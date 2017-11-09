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
     * Returns the fingeprint from a MessagePackage
     * 
     * @return fingerprint as a String
     */
    public String getFingerprint () {
        return this.msg;
    }

    public void setInitOptions (boolean conf, boolean integ, boolean auth) {
        options = new boolean[] {conf, integ, auth};
    }

    public boolean[] getOptions () {
        return options;
    }

    public byte[] getIV () {
        return iv;
    }

    public void setSymmSecretKey (SecretKey symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

    public SecretKey getSymmSecretKey () {
       return this.symmetricKey;
    }

    public void setPublicKey (PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    public PublicKey getPublicKey () {
       return this.pubKey;
    }

}