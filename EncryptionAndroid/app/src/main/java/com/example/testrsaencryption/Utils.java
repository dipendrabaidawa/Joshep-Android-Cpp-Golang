package com.example.testrsaencryption;

import android.os.Environment;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Utils {
    public static final int EOF = -1;

    public static FileInputStream openInputStream(final File file) throws IOException {
        if(file.exists()){
            if (file.isDirectory()) {
                throw new IOException("File '" + file + "' exists but is a directory");
            }
            if (file.canRead() == false) {
                throw new IOException("File '" + file + "' cannot be read");
            }
        }else {
            throw new FileNotFoundException("File '" + file + "' does not exist");
        }

        return new FileInputStream(file);
    }

    public static byte[] toByteArray(final InputStream input) throws IOException {
        final ByteArrayOutputStream output = new ByteArrayOutputStream();

        int n = EOF;
        final int kBufferSize = 1024*4;
        byte[] buf = new byte[kBufferSize];
        while (true){
            n = input.read(buf, 0, buf.length);
            if(n == EOF){
                break;
            }
            output.write(buf, 0, n);
        }
        return output.toByteArray();
    }

    public static byte[] readFileToByteArray(final File file) throws IOException {
        InputStream in = null;
        try {
            in = openInputStream(file);
            return toByteArray(in);
        } finally {
            if(in != null){
                in.close();
            }
        }
    }

    public static boolean checkExternalMedia()
    {
        boolean mExternalStorageAvailable = false;
        boolean mExternalStorageWriteable = false;
        String state = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED.equals(state)) {
            // Can read and write the media
            mExternalStorageAvailable = mExternalStorageWriteable = true;
        } else if (Environment.MEDIA_MOUNTED_READ_ONLY.equals(state)) {
            // Can only read the media
            mExternalStorageAvailable = true;
            mExternalStorageWriteable = false;
        } else {
            // Can't read or write
            mExternalStorageAvailable = mExternalStorageWriteable = false;
        }

        return (mExternalStorageAvailable && mExternalStorageWriteable);
    }

    public static byte[] decryptWithAES256Key(String encodedFile, byte[] aes256Key, byte[] iv)
            throws NoSuchPaddingException
            , NoSuchAlgorithmException
            , IOException
            , InvalidKeyException
            , BadPaddingException
            , IllegalBlockSizeException
            , InvalidAlgorithmParameterException
             {

        byte[] output = null;
        byte[] encodedBytes = Utils.readFileToByteArray(new File(encodedFile));

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv,0,iv.length);

        //Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING", Security.getProvider("BC"));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(aes256Key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        output = cipher.doFinal(encodedBytes, 0, encodedBytes.length );

        return output;
    }



    public static byte[] decryptRsaWithPrivateKey(byte[] data, PrivateKey key) throws NoSuchPaddingException
            , NoSuchAlgorithmException
            , InvalidKeyException
            , BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static boolean saveToFile(byte[] data, String path)
    {
        boolean ok = false;
        try {
            BufferedOutputStream stream = new BufferedOutputStream( new FileOutputStream(path));
            stream.write(data);
            stream.flush();
            stream.close();
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

        return ok;
    }
}
