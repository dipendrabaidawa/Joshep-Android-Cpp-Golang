package com.example.testrsaencryption;

import android.os.Handler;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class InstallerWorker {

    public enum InstallerStates {
         InitState
        , GenerateRsaKeyState
        , SaveRsaPublicKeyState
        , WaitInstallFilesState
        , DecryptFilesState
        , ClearFolderState
        , CompleteState
    }

    private KeyPair m_keyPair;
    private InstallerStates m_state = InstallerStates.InitState;
    private String m_deviceFolder;
    private String m_rsaPublicKeyFileName;
    private File m_storageFolder = null;
    private File m_sharedFolder = null;
    private File m_aesPublicKeyFile = null;
    private File[] m_encodedFiles;
    private byte[] m_aes256DataContext = null;
    private boolean m_canceled = false;
    private ReentrantLock m_locker = null;
    Handler m_handler = null;
    IInstallerWorkerListener m_listener = null;

    private void writeToLog(String str)
    {
        Log.i("AES_ENC", str);
        if(m_handler != null){
            m_handler.post(new Runnable() {
                @Override
                public void run() {
                    m_listener.writeInfo(str);
                }
            });
        }
    }

    public void reset()
    {
        m_locker.lock();
        try
        {
            m_canceled = false;
            m_state = InstallerStates.InitState;
            m_keyPair = null;
            m_encodedFiles = null;
            m_aes256DataContext = null;

            try
            {
                if(m_encodedFiles != null)
                {
                    for(int index = 0; index < m_encodedFiles.length; index++){
                        m_encodedFiles[index].delete();
                    }
                }
            }catch (Exception ex)
            {

            }
        }finally {
            m_locker.unlock();
        }
    }
    public InstallerWorker(IInstallerWorkerListener listener, Handler handler, String deviceFolder)
    {
        m_locker = new ReentrantLock();
        m_listener = listener;
        m_handler = handler;
        m_deviceFolder = deviceFolder;
        m_rsaPublicKeyFileName = "key.pub";
    }

    private void doGenerateKeyPair()
    {
        writeToLog("Generate key pair...");
        try
        {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            RSAKeyGenParameterSpec specRsa = new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4);
            generator.initialize(specRsa);
            m_keyPair = generator.generateKeyPair();
            setState(InstallerStates.SaveRsaPublicKeyState);
            writeToLog("[OK] generate key pair");
        }catch (GeneralSecurityException exception)
        {
            writeToLog("[FAILED] generate key pair:"+exception.getMessage());
            setState(InstallerStates.CompleteState);
        }
    }

    private void doSavePublicKey()
    {
        writeToLog("Save public key...");
        boolean ok = false;
        String path  = m_sharedFolder.getAbsolutePath()+"/"+m_rsaPublicKeyFileName;
        try {

            byte[] pkd = m_keyPair.getPublic().getEncoded();
            FileWriter writer = new FileWriter(path);
            writer.write("-----BEGIN PUBLIC KEY-----\n");
            writer.write(Base64.encodeToString(pkd,Base64.DEFAULT));
            writer.write("-----END PUBLIC KEY-----\n");
            writer.flush();
            writer.close();
            ok = true;
        }catch (FileNotFoundException e)
        {
            e.printStackTrace();
            Log.i("APK_SEC", "File not found. Check permissions WRITE_EXTERNAL_STORAGE err:"+e.getMessage());
        }catch (IOException ioe)
        {
            ioe.printStackTrace();
        } catch (Exception e){
            Log.e("AES_ENC", e.getMessage());
        }

        String ret = ok ?"[OK]":"[FAILED]";
        writeToLog(ret+" File write to "+path);

        if(ok){
            setState(InstallerStates.WaitInstallFilesState);
        }else{
            setState(InstallerStates.CompleteState);
        }
    }

    private void doInit()
    {
        writeToLog("Init...");
        if(Utils.checkExternalMedia())
        {
            m_storageFolder = android.os.Environment.getExternalStorageDirectory();
            m_sharedFolder = new File(m_storageFolder.getAbsolutePath()+"/"+m_deviceFolder);
            if(!m_sharedFolder.exists()){
                m_sharedFolder.mkdir();
            }

            setState(InstallerStates.GenerateRsaKeyState);
        } else {
            setState(InstallerStates.CompleteState);
        }
    }

    private void doWaitInstallFiles()
    {
        FilenameFilter filterKey = new FilenameFilter(){
            @Override
            public boolean accept(File dir, String name) {
                if(name.endsWith(".key")){
                    return true;
                }
                return false;
            }
        };

        File[] keyFiles = m_sharedFolder.listFiles(filterKey);
        if(keyFiles.length == 0){
            return;
        }

        writeToLog("Key files in shared folder:");
        for(int index = 0; index < keyFiles.length; index++){
            writeToLog(keyFiles[index].getAbsolutePath());
        }

        m_aesPublicKeyFile = keyFiles[0];

        FilenameFilter filterData = new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                if(name.endsWith(".encoded")){
                    return true;
                }
                return false;
            }
        };

        writeToLog("Encoded files in shared folder:");
        m_encodedFiles = m_sharedFolder.listFiles(filterData);
        for(int index = 0; index < m_encodedFiles.length; index++){
            writeToLog(m_encodedFiles[index].getAbsolutePath());
        }

        if(m_encodedFiles.length >= 2){
            setState(InstallerStates.DecryptFilesState);
        }
    }

    private void doDecryptInstallFiles()
    {
        writeToLog("Decrypt install files...");
        boolean ok = false;
        String debugMsg = new String();
        try {
            byte[] data = Utils.readFileToByteArray(m_aesPublicKeyFile);
            m_aes256DataContext = Utils.decryptRsaWithPrivateKey(data, m_keyPair.getPrivate());
            debugMsg = "[OK] AES256 key decoded";
            ok = true;
        } catch (FileNotFoundException exception) {
            exception.printStackTrace();
            debugMsg = exception.getMessage();
        } catch (IOException exception) {
            exception.printStackTrace();
            debugMsg = exception.getMessage();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            debugMsg = e.getMessage();
        } catch (InvalidKeyException e) {
            debugMsg = e.getMessage();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            debugMsg = e.getMessage();
        } catch (BadPaddingException e) {
            e.printStackTrace();
            debugMsg = e.getMessage();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            debugMsg = e.getMessage();
        }
        Log.i("AES_ENC:", debugMsg);

        if(!ok)
        {
            setState(InstallerStates.ClearFolderState);
            return;
        }

        //Decode files
        for(int index = 0; index < m_encodedFiles.length; index++)
        {
            //decode test file
            File encodedFile = m_encodedFiles[index];
            try {

                int ivLen = 16;
                byte[] iv = new byte[ivLen];
                byte[] aes256Key = new byte[m_aes256DataContext.length-ivLen];

                System.arraycopy(m_aes256DataContext, 0,iv, 0,iv.length);
                System.arraycopy(m_aes256DataContext, ivLen, aes256Key, 0, aes256Key.length);

                byte[] decodedData = Utils.decryptWithAES256Key(encodedFile.getAbsolutePath(), aes256Key, iv);
                Utils.saveToFile(decodedData, m_sharedFolder.getAbsolutePath()+"/"+encodedFile.getName()+".decoded");

                writeToLog(new String(decodedData));
                debugMsg = "[OK] decryptWithAES256Key";
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
                debugMsg = e.getMessage();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                debugMsg = e.getMessage();
            } catch (IOException exception) {
                exception.printStackTrace();
                debugMsg = exception.getMessage();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
                debugMsg = e.getMessage();
            } catch (BadPaddingException e) {
                e.printStackTrace();
                debugMsg = e.getMessage();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
                debugMsg = e.getMessage();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
                debugMsg = e.getMessage();
            }

            writeToLog(debugMsg);
        }

        setState(InstallerStates.ClearFolderState);
    }

    private boolean deleteDir(File dir) {
        if(dir != null){
            writeToLog(dir.getAbsolutePath());
        }

        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (int i=0; i<children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }

        return dir.delete();
    }

    public void doClearSharedFolder()
    {
        writeToLog("Clear shared folder:");
        if(m_sharedFolder != null){
            deleteDir(m_sharedFolder);
        }
    }

    void cancel()
    {
        m_locker.lock();
        try
        {
            m_canceled = true;
        }finally {
            m_locker.unlock();
        }

    }

    public boolean isCanceled()
    {
        boolean ret = false;
        m_locker.lock();
        try
        {
            ret = m_canceled;
        }finally {
            m_locker.unlock();
        }

        return ret;
    }

    public void handle()
    {
        if(isCanceled())
        {
            setState(InstallerStates.CompleteState);
        }

        switch (getState())
        {
            case InitState:{
                doInit();
            }
            break;
            case GenerateRsaKeyState:{
                doGenerateKeyPair();
            }
            break;
            case SaveRsaPublicKeyState:{
                doSavePublicKey();
            }
                break;
            case WaitInstallFilesState:
            {
                doWaitInstallFiles();
            }
                break;
            case DecryptFilesState:
            {
                doDecryptInstallFiles();
            }
                break;
            case ClearFolderState:
            {
                doClearSharedFolder();
                setState(InstallerStates.CompleteState);
            }
                break;
            case CompleteState:
                break;
        }
    }

    public InstallerStates getState()
    {
        InstallerStates ret;
        m_locker.lock();
        try
        {
            ret = m_state;
        }finally {
            m_locker.unlock();
        }

        return ret;
    }

    private void setState(InstallerStates state)
    {
        m_locker.lock();
        try
        {
            m_state = state;
        }finally {
            m_locker.unlock();
        }
    }

    public boolean isComplete()
    {
        return getState() == InstallerStates.CompleteState;
    }
}
