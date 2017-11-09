import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Message extends Remote{
    void receiveMessage (String msg) throws RemoteException;
    void receivePackage (MessagePackage pkg) throws RemoteException;
    boolean initConnection (MessagePackage pkg) throws RemoteException;
}