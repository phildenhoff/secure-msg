import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Message extends Remote {
    void receiveMessage(String msg) throws RemoteException;
}