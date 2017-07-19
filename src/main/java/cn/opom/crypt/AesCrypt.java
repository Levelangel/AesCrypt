package cn.opom.crypt;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AesCrypt {
    /**
     * length of 128
     */
    public static final int KEYLEN128 = 128;
    /**
     * length of 192
     */
    public static final int KEYLEN192 = 192;
    /**
     * length of 256
     */
    public static final int KEYLEN256 = 256;

    /**
     * Encrypt core function
     * @param content Content for encrypt
     * @param password Key for encrypting Content above
     * @param keyLen Length of the key the generator generating
     * @return
     */
    private static byte[] encrypt(String content, String password, int keyLen) {
        try {
            if(keyLen != KEYLEN128 || keyLen != KEYLEN192 || keyLen != KEYLEN256) keyLen = KEYLEN128;
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(password.getBytes());
            kgen.init(keyLen, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            byte[] byteContent = content.getBytes();
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(byteContent);
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /** Decrypt core function
     * @param content  Content for decrypt
     * @param password Key for decrypting Content above
     * @param keyLen Length of the key the generator generating
     * @return
     */
    private static byte[] decrypt(byte[] content, String password, int keyLen) {
        try {
            if(keyLen != KEYLEN128 || keyLen != KEYLEN192 || keyLen != KEYLEN256) keyLen = KEYLEN128;
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(password.getBytes());
            kgen.init(keyLen, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(content);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /** Convert byte[] to Hex string
     * @param buf Content for converting
     * @return
     */
    private static String parseByte2HexStr(byte buf[]) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (buf == null || buf.length <= 0) {
            return null;
        }
        for (int i = 0; i < buf.length; i++) {
            int v = buf[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv.toUpperCase());
        }
        return stringBuilder.toString();
    }

    /** Convert Hex string to byte[]
     * @param hexStr Content for converting
     * @return
     */
    private static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length()/2];
        char[] hexChars = hexStr.toCharArray();
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int pos = i * 2;
            result[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return result;
    }

    /**
     * Convert char to byte
     * @param c char
     * @return byte
     */
    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    /**
     * Encrypt the string
     * @param content Content for encrypt
     * @param password Key for encrypting Content above
     * @param keyLen Length of the key the generator generating
     * @return
     */
    public static String aesEncrypt(String content, String password, int keyLen){
        byte[] tmp = encrypt(content, password, keyLen);
        if(tmp == null) return null;
        return parseByte2HexStr(tmp);
    }

    /**
     * Decrypt the string
     * @param content Content for decrypt
     * @param password Key for decrypting Content above
     * @param keyLen Length of the key the generator generating
     * @return
     */
    public static String aesDecrypt(String content, String password, int keyLen){
        byte[] con = parseHexStr2Byte(content);
        byte[] tmp = decrypt(con, password, keyLen);
        if(tmp == null) return null;
        return new String(tmp);
    }
}
