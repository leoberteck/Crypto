/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.solinftec.critografia;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Windows
 */
public class EncryptDecrypt {

    private static final String UNICODE_FORMAT = "UTF8";
    public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";
    private final KeySpec ks;
    private final SecretKeyFactory skf;
    private final Cipher cipher;
    byte[] arrayBytes;
    private final String myEncryptionKey;
    private final String myEncryptionScheme;
    SecretKey key;

    public EncryptDecrypt(String key) throws Exception {
    
        myEncryptionKey = key;
        myEncryptionScheme = DESEDE_ENCRYPTION_SCHEME;
        arrayBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
        ks = new DESedeKeySpec(arrayBytes);
        skf = SecretKeyFactory.getInstance(myEncryptionScheme);
        cipher = Cipher.getInstance(myEncryptionScheme);
        this.key = skf.generateSecret(ks);
    }

    public String encrypt(String unencryptedString) {
        String encryptedString = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
            byte[] encryptedText = cipher.doFinal(plainText);
            encryptedString = new String(Base64.encodeBase64(encryptedText));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedString;
    }

    public String decrypt(String encryptedString) {
     
        String decryptedText = null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] encryptedText = Base64.decodeBase64(encryptedString.getBytes());
            byte[] plainText = cipher.doFinal(encryptedText);
            decryptedText = new String(plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedText;
    }

    private static Map<String, String> makeMap(String... args) {
        Map<String, String> argsMap = new HashMap<>();
        for (String arg : args) {
            if (arg.contains("-D")) {
                argsMap.put(arg.substring(0, arg.indexOf('=')).replace("-D", ""),
                    arg.substring(arg.indexOf('=') + 1));
            }
        }
        return argsMap;
    }

    public static void main(String args[]) throws Exception {
        Map<String, String> argsMap = makeMap(args);
        EncryptDecrypt encryptDecrypt = new EncryptDecrypt(argsMap.get("key"));

        if(argsMap.containsKey("key")){
            if(argsMap.containsKey("e")){
                System.out.println(encryptDecrypt.encrypt(argsMap.get("e")));
            } else if(argsMap.containsKey("d")){
                System.out.println(encryptDecrypt.decrypt(argsMap.get("d")));
            } else {
                System.out.println("'e' nor 'd' argument found. Pass it using -De=<yalue> or -Dd=<value>");
            }
        } else {
            System.out.println("'key' argument not found. Pass it using -Dkey=<your_key_value>");
        }
    }
}
