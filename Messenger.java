// Error handling
import java.rmi.ConnectException;
import java.rmi.RemoteException;
import java.rmi.NotBoundException;
// Importations
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Scanner;

public class Messenger implements Message {
    private boolean isServer = false;
    private boolean conf;
    private boolean integ;
    private boolean auth;
    private String hashedPass;
    private Message stub;
    private CIA me;

    /* Server-only functions */
    public void server_setup () {
        // Create messenger object as stub to allow other applications to connect
        try {
            Message serverStub = (Message) UnicastRemoteObject.exportObject(this, 0);
            Boolean notConnected = true;

            // Bind the servers' object in the registry
            Registry reg = LocateRegistry.getRegistry();
            String name = this.regName();
            while (notConnected) {
                try {
                    reg.bind(name, serverStub);
    
                    displayMsg(">>> SERVER READY");
                    displayMsg(">>> NAME: " + name);
                    notConnected = false;
                } catch (ConnectException e) {
                    java.rmi.registry.LocateRegistry.createRegistry(1099);
                } catch (Exception e) {
                    displayError(e);
                }
            }
            return;
        } catch (Exception e) {
            displayError(e);
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

    @Override
    public void receivePackage (MessagePackage pkg) {
        try {
            displayMsg(pkg.getMessage());
        } catch (Exception e) {
            displayError(e);
        }
    }

    public void sendPackage (MessagePackage pkg) {
        try {
            stub.receivePackage (pkg);
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
            MessagePackage pkg = (fp != "") ? new MessagePackage(msg, fp) : new MessagePackage(msg);
            sendPackage(pkg);
        }
    }

    /* Client-only functions */
    public void client_setup() {
        String host = null;
        try {
            Registry reg = LocateRegistry.getRegistry(host);
            stub = pickServer(reg);

            MessagePackage initPackage = new MessagePackage("Initilization from Client to Server");
            initPackage.setInitOptions(conf, integ, auth);
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

    private Message pickServer (Registry reg) {
        Message stub = null;
        String[] servers;

        try {
            servers = reg.list();
            System.out.println("Available servers:");
            for (String server : servers) {
                System.out.println("\t" + server);
            }
            while (stub == null) {
                try {
                    stub = (Message) reg.lookup(this.regName());
                } catch (NotBoundException e) {
                    // TODO: Replace with displayErr();
                    System.out.println("\nError: Invalid server name.");
                }
            }
            return stub;
        } catch (RemoteException e) {
            displayError(e);
            return null;
        }
    }

    /* Startup */
    public void setup () {
        setSecurityOptions();
        // Generate a new CIA file with given options
        try {
            me = new CIA(conf, integ, auth);        
        } catch (Exception e) {
            displayError("Not able to generate a CIA file.");
            displayError(e);
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
