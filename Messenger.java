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
import java.util.Scanner;

public class Messenger implements Message {
    private boolean isServer = false;
    boolean conf;
    boolean integ;
    boolean auth;
    String hashedPass;

    /* Server-only functions */
    public void server_setup () {
        // Create messenger object as stub to allow other applications to connect
        try {
            Messenger obj = new Messenger();
            Message stub = (Message) UnicastRemoteObject.exportObject(obj, 0);

            // Bind the servers' object in the registry
            try {
                Registry reg = LocateRegistry.getRegistry();
                String name = this.regName();
                reg.bind(name, stub);

                displayMsg(">>> SERVER READY");
                displayMsg(">>> NAME: " + name);
            } catch (Exception e) {
                displayError(e);
            }
            return;
        } catch (Exception e) {
            displayError(e);
        }
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
    public void receiveMessage (String msg) {
        // should check for all the authentication & such
        displayMsg(msg);
    }

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
        if (promptIntInput("Confidentiality: [0/1]") == 0) conf = false;
        else conf = true;
        if (promptIntInput("Integrity: [0/1]") == 0) integ = false;
        else integ = true;
        if (promptIntInput("Authentication: [0/1]") == 0) auth = false;
        else auth = true;

        return;
    }

    public void pollForInput () {
        while (true) {
            String message = promptStrInput("");

        }
    }

    /* Client-only functions */
    public void client_setup() {
        String host = null;
        try {
            Registry reg = LocateRegistry.getRegistry(host);
            Message stub = pickServer(reg);

            stub.receiveMessage("Test message to test sending messages from C -> S");
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
