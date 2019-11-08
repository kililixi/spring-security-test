package password;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

public class EncryptedUtil {
	
	// 并不是随机数，而是密钥工厂对象的密钥规范
	public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
	
	// 盐的长度
	public static final int SALT_SIZE = 16;
	
	// 密文长度
	public static final int HASH_SIZE = 32;
	
	// 迭代次数
	public static final int PBKDF2_ITERATIONS = 1000;
	
	 /** 
     * 对输入的密码进行验证 
     * 考虑到一般不会出什么问题，不抛出异常，不然后面optional不好处理
     *  
     */  
    public static boolean verify(String password, String salt, String key)  {  
        // 用相同的盐值对用户输入的密码进行加密  
        String result = "";
		try {
			result = getPBKDF2(password, salt);
		} catch (NoSuchAlgorithmException e) {
			// TODO 记录日志
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO 记录日志
			e.printStackTrace();
		}  
        // 把加密后的密文和原密文进行比较，相同则验证成功，否则失败  
        return result.equals(key);  
    }  
    
    /**
     * 根据password和salt生成密文
     * 
     */
    public static String getPBKDF2(String password, String salt) throws NoSuchAlgorithmException,  
            InvalidKeySpecException {  
    	//将16进制字符串形式的salt转换成byte数组
    	byte[] bytes = DatatypeConverter.parseHexBinary(salt);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), bytes, PBKDF2_ITERATIONS, HASH_SIZE * 4);  
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);  
        byte[] hash = secretKeyFactory.generateSecret(spec).getEncoded();
		//将byte数组转换为16进制的字符串
        return DatatypeConverter.printHexBinary(hash);  
    }  
  
    /** 
     * 生成随机盐值
     *  
     */  
    public static String getSalt() throws NoSuchAlgorithmException {  
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");  
        byte[] bytes = new byte[SALT_SIZE / 2];  
        random.nextBytes(bytes);  
        //将byte数组转换为16进制的字符串
        String salt = DatatypeConverter.printHexBinary(bytes);
        return salt;  
    }  
	
}