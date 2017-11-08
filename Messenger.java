public class Messenger {
    boolean conf;
    boolean integ;
    boolean auth;
    String hashedPass;

    /* Server functions */
    public void initServer () {
    }

    /* Client functions*/
    public void displayMsg (String msg) {
        System.out.println(msg);
    }

    public void displayError (String msg) {
        System.err.println( (char) 27 + "[31mERROR: " + msg);
    }

    /* Startup */
    public void setup () {
        displayMsg("Initialised Server");
        displayError("Oh no, I had a problem!");
    }

    public static void main(String[] args) {
        Messenger us = new Messenger();
        us.setup();
    }
}
