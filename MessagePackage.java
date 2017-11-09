import java.io.Serializable;
/**
 * Defines a MessagePackage to send to the other system
 */
class MessagePackage implements java.io.Serializable {
    private String msg;
    private String fp;
    private byte[] iv;
    private boolean[] options;

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
}