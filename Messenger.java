// Exceptions
import java.rmi.ConnectException;
import java.rmi.RemoteException;
import java.rmi.NotBoundException;
import java.io.IOException;

// Importations
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Scanner;
// File reading
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class Messenger implements Message {
    /**
	 * True if the device is the server
	 */
	private boolean isServer = false;
    /**
	 * True if user selected confidentiality
	 */
	private boolean conf;
    /**
	 * True if user selected integrity
	 */
	private boolean integ;
    /**
	 * True if user selected authentication
	 */
	private boolean auth;
    /**
	 * The client's connection to the server
	 */
	private Message stub;
    /**
	 * Our instance of the CIA class
	 */
	private CIA me;
    /**
	 * The device's name in the RMI registry
	 */
	private String localName;
    /**
	 * The server's connection to the client
	 */
	private Message theirStub;

    /* Server-only functions */

    /**
     * Setup secure-msg server. Connects (and initizalises) RMI registrry with name from user.
     */
    public void server_setup () {
        // Create messenger object as stub to allow other applications to connect
        try {
            Message serverStub = (Message) UnicastRemoteObject.exportObject(this, 0);
            registerWithRMI(serverStub);
        } catch (Exception e) {
            displayError(e);
        }
    }

    /**
     * Register with registry to allow 2-way RMI communication. Sets localName.
     * 
     * @param Message serverStub : registry to register with.
     */
    public void registerWithRMI (Message serverStub) throws Exception {
        // Bind the servers' object in the registry
        Registry reg = LocateRegistry.getRegistry();
        Boolean notConnected = true;
        if (isServer) {
            localName = this.regName();            
        } else {
            localName = "client";
        }
        while (notConnected) {
            try {
                reg.bind(localName, serverStub);

                displayMsg(">>> DEVICE READY");
                displayMsg(">>> NAME: " + localName);
                notConnected = false;
            } catch (ConnectException e) {
                java.rmi.registry.LocateRegistry.createRegistry(1099);
            } catch (Exception e) {
                displayError(e);
            }
        }
    }

    /**
     * Connect only if we can prove their init message follows all our requirements.
     * @param MessagePackage: pkg should include security options, fingerprint (if necessary), public key, and symmetric key.
     */
    @Override
    public boolean initConnection (MessagePackage pkg) {
        boolean validInit = true;
        
        // Check options
        boolean[] theirOptions = pkg.getOptions();
        String badOptions = "";
        if (theirOptions[0] != this.conf) {
            badOptions += "'conf' ";
            validInit = false;
        }
        if (theirOptions[1] != this.integ) {
            badOptions += "'integ' ";
            validInit = false;
        }
        if (theirOptions[1] != this.auth) {
            badOptions += "'auth' ";
            validInit = false;
        }
        if (badOptions != "" ) displayError("User tried to connect with incorrect " + badOptions + "option(s).");

        try {
            Registry reg = LocateRegistry.getRegistry();            
            theirStub = (Message) reg.lookup(pkg.getDeviceName());
        } catch (NotBoundException e) {
            displayError("\nError: Invalid device name.");
        } catch (Exception e) {
            displayError(e);
        }
        try {
            theirStub.receiveMessage(localName + " connected to you!");
        } catch (Exception e) {
            displayError("Unable to send message");
            displayError(e);
        }
        
        displayMsg(pkg.getDeviceName());
        // Get public key
        // TODO: ADD PUBLIC KEY

        //

        return validInit;
    }

    /* General functions*/

    /**
     * Display a message to the user.
     * 
     * @param String Message to display
     */
    public void displayMsg (String msg) {
        System.out.println(msg);
    }

    /**
     * Display an error to the user.
     * 
     * @param Exception exception to display
     */
    public void displayError (Exception e) {
        System.err.println((char) 27 + "[31m Client exception: " + e.toString());
        e.printStackTrace();
    }
    /**
     * Display an error to the user.
     * 
     * @param String exception to display
     */
    public void displayError (String msg) {
        System.err.println( (char) 27 + "[31mERROR: " + msg);
    }

    /**
     * Get user string input to a prompt.
     * 
     * @param String message to prompt user for unput
     * @return Users unprocessed input string
     */
    public String promptStrInput (String msg) {
        if (msg != "") displayMsg(msg);
        Scanner scanner = new Scanner(System.in);
        String val = scanner.nextLine();
        return val;
    }

    /**
     * Get user integer input to a prompt.
     * 
     * @param String message to prompt user for unput
     * @return Users unprocessed input int
     */
    public int promptIntInput (String msg) {
        if (msg != "") displayMsg(msg);
        Scanner scanner = new Scanner(System.in);
        int val = scanner.nextInt();
        scanner.nextLine();
        return val;
    }

    @Override
    @Deprecated
    public void receiveMessage (String msg) {
        // should check for all the authentication & such
        displayMsg(msg);
    }

    /**
     * Receive packages from remote system, decrypts if need be, verifies integrity, and displays messages.
     * 
     * @param MessagePackage: package to receive
     */
    @Override
    public void receivePackage (MessagePackage pkg) {
        try {
            displayMsg(pkg.getMessage());
        } catch (Exception e) {
            displayError(e);
        }
    }

    /**
     * Send MessagePackage from local to remote (client to server or vice versa).
     * 
     * @param MessagePackage: pkg to send
     */
    public void sendPackage (MessagePackage pkg) {
        try {
            if (isServer) theirStub.receivePackage(pkg);
            else stub.receivePackage (pkg);
        } catch (Exception e) {
            displayError("Message not delivered: \'" + pkg.getMessage() + "\'");
            displayError(e);
        }
    }

    /**
     * Let user select server name from registry
     */
    public String regName () {
        String mode = (isServer) ? "SERVER MODE" : "CLIENT MODE";
        System.out.printf("(%s) Enter the server name:%n", mode);
        String name = promptStrInput("");
        return name;
    }

    /**
     * Prompts the user for their security options and sets the sessions variables.
     */
    public void setSecurityOptions () {
        displayMsg("What security options would you like? You'll be prompted for a numerical response, and options are default-on.");
        if (promptIntInput("Confidentiality: [0/1]") == 0) this.conf = false;
        else this.conf = true;
        if (promptIntInput("Integrity: [0/1]") == 0) this.integ = false;
        else this.integ = true;
        if (promptIntInput("Authentication: [0/1]") == 0) this.auth = false;
        else this.auth = true;
    }

    /**
     * General waiting state after the system is set up. Users are able to input text at any time.
     */
    public void pollForInput () {
        while (true) {
            String msg = promptStrInput("");
            String fp = "";
            byte[] iv = me.generateIV();
            try {
                if (conf) msg = me.encryptSymmetric(msg, iv);
            } catch (Exception e) {
                displayError("Unable to enrypt messages.");
                displayError(e);
            }
            displayMsg(msg);
            // if (integ) fp = fingerprint(message); 
            // MessagePackage pkg = (fp != "") ? new MessagePackage(msg, fp) : new MessagePackage(msg);
            MessagePackage pkg = new MessagePackage(msg, fp);
            sendPackage(pkg);
        }
    }

    /**
     * Authenticate local user with stored password.
     */
    private boolean authenticate() {
        boolean authenticated = false;
        String fileName = "./secure/pass"; // definitely Linux compatible. Not sure about Windows.
        String localPass = "";
        String hashedLocal;
        String inputPass;
        String hashedInput;

        try {
            localPass = new String(Files.readAllBytes(Paths.get(fileName))).replaceAll("\\s+","");  // Read passfile from file and strip whitespace
            hashedLocal = me.hashString(localPass);
            inputPass = promptStrInput("Enter password:").replaceAll("\\s+","");  // strip whitespace from input
            hashedInput = me.hashString(inputPass);

            if (hashedInput.equals(hashedLocal)) authenticated = true;
            else {
                displayMsg("Password does not match.");
            }
        } catch (IOException e) {
            displayError("./secure/pass file missing or inaccessible");
            displayError(e);
            System.exit(1);
        } catch (Exception e) {
            displayError(e);
        }
        // Return that the hashes are the same
        return authenticated;
    }

    /* Client-only functions */
    public void client_setup() {
        String host = null;
        try {
            Registry reg = LocateRegistry.getRegistry(host);
            stub = pickServer(reg);
            Message serverStub = (Message) UnicastRemoteObject.exportObject(this, 0);            
            registerWithRMI(serverStub);

            MessagePackage initPackage = new MessagePackage("Initilization from Client to Server");
            initPackage.setInitOptions(conf, integ, auth);
            initPackage.setDeviceName(localName);
            boolean connected = stub.initConnection(initPackage);
            if (connected) displayMsg("Connected to server.");
            else {
                displayError("Disconnected from server. Check security options.");
                System.exit(1);
            }
            // stub.receiveMessage("Test message to test sending messages from C -> S");
        } catch (ConnectException e) {
            displayError("Error: Server refused to connect.");
        } catch (Exception e) {
            displayError(e);
        }
    }

    /**
     * Lists servers in registry and prompts user to select a server to connect to.
     */
    private Message pickServer (Registry reg) {
        Message stub = null;
        String[] servers;

        try {
            servers = reg.list();
            displayMsg("Available servers:");
            for (String server : servers) {
                displayMsg("\t" + server);
            }
            while (stub == null) {
                try {
                    stub = (Message) reg.lookup(this.regName());
                } catch (NotBoundException e) {
                    // TODO: Replace with displayErr();
                    displayError("\nError: Invalid server name.");
                }
            }
            return stub;
        } catch (RemoteException e) {
            displayError(e);
            return null;
        }
    }

    /* Startup */

    /**
     * Set up Messenger, whether client or server. Get security options, generate CIA, prompt for authentication, and check if
     * program is server or client.
     */
    public void setup () {
        setSecurityOptions();

        // Generate a new CIA file with given options
        try {
            me = new CIA(conf, integ, auth);        
        } catch (Exception e) {
            displayError("Not able to generate a CIA file.");
            displayError(e);
        }

        if (auth) { // Requires CIA file to be set up first
            if (!authenticate()) System.exit(1);
        }

        // Pick client or server
        String mode = this.promptStrInput("Are you a client or the server? [C/S]").toLowerCase();
        if (mode.equals("s")) {
            isServer = true;
            this.server_setup();
        } else {
            this.client_setup();
        }

        pollForInput();
    }

    public static void main(String[] args) {
        Messenger us = new Messenger();
        us.setup();
    }
}
