/**
 * Copyright (c) 2009-2013 InfoShip Corporation. All rights reserved. 
 */
package com.mayisoft.license.util;

import net.sf.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.util.Calendar;
import java.util.logging.Logger;

/**
 * @author yuan
 * @date 2013-7-13
 */
public class LicenseGenerator {

    private static Logger logger = Logger.getLogger(LicenseGenerator.class.getName());

    /**
	 * 进行MD5加密
	 * 
	 * @param info
	 *          要加密的信息
	 * @return String 加密后的字符串
	 */
	public String encryptToMD5(String info) {
		byte[] digesta = null;
		try {
			// 得到一个md5的消息摘要
			MessageDigest alga = MessageDigest.getInstance("MD5");
			// 添加要进行计算摘要的信息
			alga.update(info.getBytes());
			// 得到该摘要
			digesta = alga.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		// 将摘要转为字符串
		String rs = byte2hex(digesta);
		return rs;
	}

	/**
	 * 进行SHA加密
	 * 
	 * @param info
	 *          要加密的信息
	 * @return String 加密后的字符串
	 */
	public String encryptToSHA(String info) {
		byte[] digesta = null;
		try {
			// 得到一个SHA-1的消息摘要
			MessageDigest alga = MessageDigest.getInstance("SHA-1");
			// 添加要进行计算摘要的信息
			alga.update(info.getBytes());
			// 得到该摘要
			digesta = alga.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		// 将摘要转为字符串
		String rs = byte2hex(digesta);
		return rs;
	}
	
	/**
	 * 创建密匙
	 * 
	 * @param algorithm
	 *          加密算法,可用 DES,DESede,Blowfish
	 * @return SecretKey 秘密（对称）密钥
	 */
	public SecretKey createSecretKey(String algorithm) {
		// 声明KeyGenerator对象
		KeyGenerator keygen;
		// 声明 密钥对象
		SecretKey deskey = null;
		try {
			// 返回生成指定算法的秘密密钥的 KeyGenerator 对象
			keygen = KeyGenerator.getInstance(algorithm);
			// 生成一个密钥
			deskey = keygen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		// 返回密匙
		return deskey;
	}

	/**
	 * 根据密匙进行DES加密
	 * 
	 * @param key
	 *          密匙
	 * @param info
	 *          要加密的信息
	 * @return String 加密后的信息
	 */
	public String encryptToDES(SecretKey key, String algorithm, String info) {
		// 定义 加密算法,可用 DES,DESede,Blowfish
		// 加密随机数生成器 (RNG),(可以不写)
		SecureRandom sr = new SecureRandom();
		// 定义要生成的密文
		byte[] cipherByte = null;
		try {
			// 得到加密/解密器
			Cipher c1 = Cipher.getInstance(algorithm);
			// 用指定的密钥和模式初始化Cipher对象
			// 参数:(ENCRYPT_MODE, DECRYPT_MODE, WRAP_MODE,UNWRAP_MODE)
			c1.init(Cipher.ENCRYPT_MODE, key, sr);
			// 对要加密的内容进行编码处理,
			cipherByte = c1.doFinal(info.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		// 返回密文的十六进制形式
		return byte2hex(cipherByte);
	}
	
	/**
	 * 创建密匙组，并将公匙，私匙放入到指定文件中
	 * 
	 * 默认放入privatekeys.ks文件中
	 */
	public void createPairKey() {
		try {
			// 根据特定的算法一个密钥对生成器
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
			// 加密随机数生成器 (RNG)
			SecureRandom random = new SecureRandom();
			// 重新设置此随机对象的种子
			random.setSeed(1000);
			// 使用给定的随机源（和默认的参数集合）初始化确定密钥大小的密钥对生成器
			keygen.initialize(512, random);// keygen.initialize(512);
			// 生成密钥组
			KeyPair keys = keygen.generateKeyPair();
			// 得到公匙
			PublicKey pubkey = keys.getPublic();
			// 得到私匙
			PrivateKey prikey = keys.getPrivate();
			// 将公匙私匙写入到文件当中
			doObjToFile("privatekeys.ks", new Object[] { prikey, pubkey });
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 利用私匙对信息进行签名 把签名后的信息放入到指定的文件中
	 * 
	 * @param info
	 *          要签名的信息
	 * @param signfile
	 *          存入的文件
	 */
	public void signToInfo(String info, String signfile) {
		// 从文件当中读取私匙
		PrivateKey myprikey = (PrivateKey) getObjFromFile("privatekeys.ks", 1);
		// 从文件中读取公匙
		PublicKey mypubkey = (PublicKey) getObjFromFile("privatekeys.ks", 2);
		try {
			// Signature 对象可用来生成和验证数字签名
			Signature signet = Signature.getInstance("DSA");
			// 初始化签署签名的私钥
			signet.initSign(myprikey);
			// 更新要由字节签名或验证的数据
			signet.update(info.getBytes());
			// 签署或验证所有更新字节的签名，返回签名
			byte[] signed = signet.sign();
			// 将数字签名,公匙,信息放入文件中
			doObjToFile(signfile, new Object[] { signed, mypubkey, info });
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 将二进制转化为16进制字符串
	 * 
	 * @param b
	 *          二进制字节数组
	 * @return String
	 */
	public String byte2hex(byte[] b) {
		String hs = "";
		String stmp = "";
		for (int n = 0; n < b.length; n++) {
			stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
			if (stmp.length() == 1) {
				hs = hs + "0" + stmp;
			} else {
				hs = hs + stmp;
			}
		}
		return hs.toUpperCase();
	}

	/**
	 * 十六进制字符串转化为2进制
	 * 
	 * @param hex
	 * @return
	 */
	public byte[] hex2byte(String hex) {
		byte[] tmp = hex.getBytes();
		// byte[] ret = new byte[32];
		byte[] ret = new byte[tmp.length / 2];
		for (int i = 0; i < tmp.length / 2; i++) {
			ret[i] = uniteBytes(tmp[i * 2], tmp[i * 2 + 1]);
		}
		return ret;
	}

	/**
	 * 将两个ASCII字符合成一个字节； 如："EF"--> 0xEF
	 * 
	 * @param src0
	 *          byte
	 * @param src1
	 *          byte
	 * @return byte
	 */
	public static byte uniteBytes(byte src0, byte src1) {
		byte _b0 = Byte.decode("0x" + new String(new byte[] { src0 })).byteValue();
		_b0 = (byte) (_b0 << 4);
		byte _b1 = Byte.decode("0x" + new String(new byte[] { src1 })).byteValue();
		byte ret = (byte) (_b0 ^ _b1);
		return ret;
	}

	/**
	 * 将指定的对象写入指定的文件
	 * 
	 * @param file
	 *          指定写入的文件
	 * @param objs
	 *          要写入的对象
	 */
	public void doObjToFile(String file, Object[] objs) {
		ObjectOutputStream oos = null;
		try {
			FileOutputStream fos = new FileOutputStream(file);
			oos = new ObjectOutputStream(fos);
			for (int i = 0; i < objs.length; i++) {
				oos.writeObject(objs[i]);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				oos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * 返回在文件中指定位置的对象
	 * 
	 * @param file
	 *          指定的文件
	 * @param i
	 *          从1开始
	 * @return
	 */
	public Object getObjFromFile(String file, int i) {
		ObjectInputStream ois = null;
		Object obj = null;
		try {
			FileInputStream fis = new FileInputStream(file);
			ois = new ObjectInputStream(fis);
			for (int j = 0; j < i; j++) {
				obj = ois.readObject();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				ois.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return obj;
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String macAddress="68-A8-6D-20-E8-10";
		String email = "yqx@infoship.cn";
		Calendar expireCal = Calendar.getInstance();
//		expireCal.roll(Calendar.MONTH, -1);//过期
		expireCal.add(Calendar.MONTH, 1);//试用一个月
//		expireCal.add(Calendar.MONTH, 6);//半年授权
//		expireCal.add(Calendar.MONTH, 12);//1年授权
//		expireCal.add(Calendar.YEAR, 99);//永久授权
		logger.info(String.format("%tF",expireCal.getTime(),expireCal.getTime()));
		JSONObject plainInfo = new JSONObject();
		plainInfo.accumulate("ma", macAddress);
		plainInfo.accumulate("em", email);
		plainInfo.accumulate("ex", expireCal.getTimeInMillis());
		logger.info(plainInfo.toString());
		LicenseGenerator licenseGen = new LicenseGenerator();
//		String algorithm = "DESede";
//		SecretKey key = licenseGen.createSecretKey(algorithm);
//		String enctyptInfo = licenseGen.encryptToDES(key, algorithm, plainInfo.toString());
		licenseGen.createPairKey();
        String signfile = new StringBuilder(System.getProperty("java.io.tmpdir")).append(File.separator)
                .append("license-tool").append(File.separator).append("license.lic").toString();
        File destDir = new File(signfile).getParentFile();
        /*if (!destDir.isDirectory()) {
            throw new IllegalArgumentException(destDir.getPath());
        }*/
        if (!destDir.exists()) {
            destDir.mkdirs();
        }
        licenseGen.signToInfo(plainInfo.toString(), signfile);
        logger.info("成功生成授权文件: " + signfile);
	}

}
