package com.mikel.finalbtchat;

import static androidx.constraintlayout.helper.widget.MotionEffect.TAG;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.biometric.BiometricPrompt;

import android.annotation.SuppressLint;
import android.os.Bundle;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.Intent;
import android.os.Handler;
import android.os.Message;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;

import android.util.Base64;
import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity {
    Button listen,send, listDevices, conectarse;
    ListView listView;
    TextView msg_box,status;
    EditText writeMsg;
    BluetoothAdapter bluetoothAdapter;
    BluetoothDevice[] btArray;
    SendReceive sendReceive;
    public BiometricPrompt biometricPrompt;
    private Executor executor;
    private BiometricPrompt.PromptInfo promptInfo;
    private RsaEncryptDecryt rsa;
    static final int STATE_LISTENING = 1;
    static final int STATE_CONNECTING=2;
    static final int STATE_CONNECTED=3;
    static final int STATE_CONNECTION_FAILED=4;
    static final int STATE_MESSAGE_RECEIVED=5;
    static final String SOLICITAR_ACCESO = "100";
    static final String SMS_AUTENTICATION_CORRECT = "200";
    static final String BIOMETRIC_AUTENTICATION_CORRECT = "201";
    static final String START_RFID_READER = "202";
    static final String RFID_AUTENTICATION_CORRECT = "203";
    int REQUEST_ENABLE_BLUETOOTH=1;
    private static final String APP_NAME = "BTChat";
    private static final UUID MY_UUID=UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewByIdes();
        bluetoothAdapter=BluetoothAdapter.getDefaultAdapter();

        if(!bluetoothAdapter.isEnabled())
        {
            Intent enableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            startActivityForResult(enableIntent,REQUEST_ENABLE_BLUETOOTH);
        }

        implementListeners();
        iniciarBiometria();

    }

    private class RsaEncryptDecryt{

        private KeyPairGenerator kpg;
        private KeyPair kp;
        private PublicKey publicKey;
        private PrivateKey privateKey;

        private PublicKey rasp_public_key;

        private String descryptedString;
        private byte[] encrytedByte;
        private byte[] descryptedByte;
        private Cipher cipher;

        private final static String CRYPTO_METHOD = "RSA";
        private final static int CRYPTO_BITS = 2048;
        private final static String OPCION_RSA= "RSA/ECB/OAEPWithSHA1AndMGF1Padding";

        //Función de generación de claves publica/privada RSA
        private void generateKeyPair() throws Exception{
            kpg = KeyPairGenerator.getInstance(CRYPTO_METHOD);
            kpg.initialize(CRYPTO_BITS);
            kp = kpg.generateKeyPair();
            //Guardamos la clave publica generada para mandarla a la Raspberry y cifre sus mensajes
            rasp_public_key = kp.getPublic();
            Log.d("TAG1", "public key -> " + publicKey);
            //La clave privada la guardamos para desencriptar los mensajes recibidos
            privateKey = kp.getPrivate();
            Log.d("TAG1", "private key -> " + privateKey);
        }

        //Función para encriptar mensajes con la clave pública recibida de la Raspberry
        private String encrypt(String mensajeAEncriptar) throws Exception{
            cipher = Cipher.getInstance(OPCION_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encrytedByte = cipher.doFinal(mensajeAEncriptar.getBytes());
            return Base64.encodeToString(encrytedByte, Base64.DEFAULT);
        }

        //FUnción desencriptar mensajes
        private String descrypt(String result) throws Exception{
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            descryptedByte = cipher.doFinal(Base64.decode(result, Base64.DEFAULT));
            descryptedString = new String(descryptedByte);
            return descryptedString;
        }

        //Función para convertir la clave pública recibida en objeto PublicKey
        private PublicKey convertStringToPublicKey(String publicKeyString) throws Exception {
            // Eliminar posibles encabezados o pies (headers/footers) de PEM
            publicKeyString = publicKeyString.replaceAll("\\n", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");

            // Decodificar la cadena Base64 utilizando android.util.Base64
            byte[] publicKeyBytes = Base64.decode(publicKeyString, Base64.DEFAULT);

            // Crear una especificación de clave pública
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

            // Obtener una instancia de la fábrica de claves
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Puedes ajustar el algoritmo según tu necesidad

            // Generar la clave pública a partir de la especificación
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            return publicKey;
        }

        //Función para convertir objeto PublicKey en cadena de texto para ser enviada
        private String convertPublicKeyToString(PublicKey publicKey) throws Exception {
            // Obtener la codificación de la clave pública
            byte[] publicKeyBytes = publicKey.getEncoded();

            // Codificar la clave pública en Base64 utilizando android.util.Base64
            String publicKeyString = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT);

            // Formatear la cadena según el formato PEM
            StringBuilder pemPublicKey = new StringBuilder();
            pemPublicKey.append("-----BEGIN PUBLIC KEY-----\n");
            pemPublicKey.append(publicKeyString);
            pemPublicKey.append("\n-----END PUBLIC KEY-----\n");

            return pemPublicKey.toString();
        }
    }

    //Función de inicialización de sistema biométrico
    private void iniciarBiometria(){
        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Autenticación biométrica")
                .setSubtitle("Usa tu huella digital para autenticarte")
                .setNegativeButtonText("Cancelar")
                .build();
        executor = ContextCompat.getMainExecutor(this);

        biometricPrompt = new BiometricPrompt(MainActivity.this,
                executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(),
                                "Error de autenticación: " + errString, Toast.LENGTH_SHORT)
                        .show();
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);

                Toast.makeText(getApplicationContext(),
                        "¡Autenticación exitosa!", Toast.LENGTH_SHORT).show();

                try{
                    //Enviamos código de confirmación de autenticación biométrica exitosa
                    String mensaje_encriptado = rsa.encrypt(BIOMETRIC_AUTENTICATION_CORRECT);
                    sendReceive.write(mensaje_encriptado.getBytes());
                }
                catch(Exception e){

                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(getApplicationContext(), "Autenticación fallida",
                                Toast.LENGTH_SHORT)
                        .show();
            }
        });
    }

    //Funcion de inicialización de listeners
    private void implementListeners() {

        //Listener para crear una lista de dispositivos bluetooth del entorno
        listDevices.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Set<BluetoothDevice> bt=bluetoothAdapter.getBondedDevices();
                String[] strings=new String[bt.size()];
                btArray=new BluetoothDevice[bt.size()];
                int index=0;

                if( bt.size()>0)
                {
                    for(BluetoothDevice device : bt)
                    {
                        btArray[index]= device;
                        strings[index]=device.getName();
                        index++;
                    }
                    ArrayAdapter<String> arrayAdapter=new ArrayAdapter<String>(getApplicationContext(),android.R.layout.simple_list_item_1,strings);
                    listView.setAdapter(arrayAdapter);
                }
            }
        });

/*
        listen.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ServerClass serverClass=new ServerClass();
                serverClass.start();
            }
        });
*/
        //Listener para hacer un intento de conexión con un dispositvo bluetooth seleccionado de la lista.
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int i, long l) {
                ClientClass clientClass=new ClientClass(btArray[i]);
                clientClass.start();
                status.setText("Conectando");
            }
        });

        //Listener para envío de codigo al pulsar la tecla ENVIAR
        send.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try{
                    String string= String.valueOf(writeMsg.getText());
                    String mensaje_encriptado = rsa.encrypt(string);
                    sendReceive.write(mensaje_encriptado.getBytes());
                }
                catch(Exception e){
                }
            }
        });
    }

    Handler handler=new Handler(new Handler.Callback() {
        @Override
        public boolean handleMessage(Message msg) {

            switch (msg.what)
            {
                case STATE_LISTENING:
                    status.setText("ESCUCHANDO");
                    break;
                case STATE_CONNECTING:
                    status.setText("CONECTANDO");
                    break;
                case STATE_CONNECTED:
                    status.setText("CONEXIÓN ESTABLECIDA");
                    break;
                case STATE_CONNECTION_FAILED:
                    status.setText("CONEXIÓN FALLLIDA");
                    break;
                case STATE_MESSAGE_RECEIVED:
                    byte[] readBuff= (byte[]) msg.obj;
                    String tempMsg=new String(readBuff,0,msg.arg1);
                    msg_box.setText(tempMsg);

                    try{
                        tempMsg = rsa.descrypt(tempMsg);
                    }
                    catch (Exception e ){

                    }
                    switch(tempMsg){
                        case SMS_AUTENTICATION_CORRECT:
                            msg_box.setText(tempMsg + " - CÓDIGO CORRECTO");
                            biometricPrompt.authenticate(promptInfo);
                            break;
                        case BIOMETRIC_AUTENTICATION_CORRECT:
                            break;
                        case START_RFID_READER:
                            msg_box.setText(tempMsg + " - PASE LA TARJETA POR EL LECTOR");
                            break;
                        case RFID_AUTENTICATION_CORRECT:
                            msg_box.setText(tempMsg + " - ACCESO AUTORIZADO. PUERTA ABIERTA");
                            break;
                        default:
                            Log.d("TAG1", "public key de raspberry PI-> " + tempMsg);
                            rsa = new RsaEncryptDecryt();
                            try{
                                rsa.publicKey = rsa.convertStringToPublicKey(tempMsg);
                                Log.d("TAG1", "public key en public-> " + rsa.publicKey);
                                rsa.generateKeyPair();

                                //ENVIAR CLAVE PUBLICA A RASPBERRY
                                String clave_publica_para_mandar = rsa.convertPublicKeyToString(rsa.rasp_public_key);
                                sendReceive.write(clave_publica_para_mandar.getBytes());

                                //Solicitamos acceso  e inicio de autenticación
                                String mensajeEncriptado = rsa.encrypt(SOLICITAR_ACCESO);
                                sendReceive.write(mensajeEncriptado.getBytes());
                            }
                            catch(Exception e){

                            }
                            break;
                    }
                    break;
            }
            return true;
        }
    });

    //Creamos instancias de los componentes UI
    private void findViewByIdes() {
        listen=(Button) findViewById(R.id.listen);
        send=(Button) findViewById(R.id.sendButton);
        listView=(ListView) findViewById(R.id.listview);
        msg_box =(TextView) findViewById(R.id.msg);
        status=(TextView) findViewById(R.id.status);
        writeMsg=(EditText) findViewById(R.id.writemsg);
        listDevices=(Button) findViewById(R.id.listDevices);
    }
/*
    //Clase privada para la conexión bluetooth y creación de cliente socket RFComm
    private class ServerClass extends Thread
    {
        private BluetoothServerSocket serverSocket;
        @SuppressLint("MissingPermission")
        public ServerClass(){
            try {
                serverSocket=bluetoothAdapter.listenUsingRfcommWithServiceRecord(APP_NAME,MY_UUID);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void run()
        {
            BluetoothSocket socket=null;

            while (socket==null)
            {
                try {
                    Message message=Message.obtain();
                    message.what=STATE_CONNECTING;
                    handler.sendMessage(message);

                    socket=serverSocket.accept();
                } catch (IOException e) {
                    e.printStackTrace();
                    Message message=Message.obtain();
                    message.what=STATE_CONNECTION_FAILED;
                    handler.sendMessage(message);
                }

                if(socket!=null)
                {
                    Message message=Message.obtain();
                    message.what=STATE_CONNECTED;
                    handler.sendMessage(message);

                    sendReceive=new SendReceive(socket);
                    sendReceive.start();
                    break;
                }
            }
        }
    }
*/
    private class ClientClass extends Thread
    {
        private BluetoothDevice device;
        private BluetoothSocket socket;

        public ClientClass (BluetoothDevice device1)
        {
            device=device1;

            try {
                socket=device.createRfcommSocketToServiceRecord(MY_UUID);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void run()
        {

            try {
                socket.connect();
                Message message=Message.obtain();
                message.what=STATE_CONNECTED;
                handler.sendMessage(message);

                sendReceive=new SendReceive(socket);
                sendReceive.start();

            } catch (IOException e) {
                try {
                    socket.close();
                } catch (IOException closeException) {
                    Log.e(TAG, "Could not close the client socket", closeException);
                }
                e.printStackTrace();
                Message message=Message.obtain();
                message.what=STATE_CONNECTION_FAILED;
                handler.sendMessage(message);
            }
        }

        public void cancel() {
            try {
                socket.close();
            } catch (IOException e) {
                Log.e(TAG, "Could not close the client socket", e);
            }
        }
    }

    //Clase para el envío y recepcion de mensaje mediante socket bluetooth
    private class SendReceive extends Thread
    {
        private final BluetoothSocket bluetoothSocket;
        private final InputStream inputStream;
        private final OutputStream outputStream;

        public SendReceive (BluetoothSocket socket)
        {
            bluetoothSocket=socket;
            InputStream tempIn=null;
            OutputStream tempOut=null;

            try {
                tempIn=bluetoothSocket.getInputStream();
                tempOut=bluetoothSocket.getOutputStream();
            } catch (IOException e) {
                e.printStackTrace();
            }

            inputStream=tempIn;
            outputStream=tempOut;
        }

        public void run()
        {
            byte[] buffer=new byte[1024];
            int bytes;

            while (true)
            {
                try {
                    bytes=inputStream.read(buffer);
                    handler.obtainMessage(STATE_MESSAGE_RECEIVED,bytes,-1,buffer).sendToTarget();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        public void write(byte[] bytes)
        {
            try {
                outputStream.write(bytes);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}