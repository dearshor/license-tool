package com.mayisoft.license.test;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.PublicKey;
import java.security.Signature;

import net.sf.json.JSONObject;

import org.junit.Test;

import com.mayisoft.license.LicenseUtil;

public class LicenseValidate {

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
	 * 读取数字签名文件 根据公匙，签名，信息验证信息的合法性
	 * 
	 * @return true 验证成功 false 验证失败
	 */
	public boolean validateSign(String signfile) {
		// 读取公匙
		PublicKey mypubkey = (PublicKey) getObjFromFile(signfile, 2);
		// 读取签名
		byte[] signed = (byte[]) getObjFromFile(signfile, 1);
		// 读取信息
		String info = (String) getObjFromFile(signfile, 3);
		try {
			// 初始一个Signature对象,并用公钥和签名进行验证
			Signature signetcheck = Signature.getInstance("DSA");
			// 初始化验证签名的公钥
			signetcheck.initVerify(mypubkey);
			// 使用指定的 byte 数组更新要签名或验证的数据
			signetcheck.update(info.getBytes());
			// 验证传入的签名
			boolean signedCheck = signetcheck.verify(signed);
			if(!signedCheck)
				return false;
			JSONObject infoJson = JSONObject.fromObject(info);
			String macaddressOfLicense = infoJson.getString("ma");
			InetAddress ia = InetAddress.getLocalHost();// 获取本地IP对象
			String macaddress = getMACAddress(ia);
			return macaddress.equals(macaddressOfLicense);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	/**
	 * 返回在文件中指定位置的对象
	 * 
	 * @param file
	 *            指定的文件
	 * @param i
	 *            从1开始
	 * @return
	 */
	public Object getObjFromFile(String file, int i) {
		ObjectInputStream ois = null;
		Object obj = null;
		try {
			InputStream fis = LicenseUtil.class.getResourceAsStream(file);//new FileInputStream(file);
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
	
//获取MAC地址的方法
	private static String getMACAddress(InetAddress ia) throws Exception {
		// 获得网络接口对象（即网卡），并得到mac地址，mac地址存在于一个byte数组中。
		byte[] mac = NetworkInterface.getByInetAddress(ia).getHardwareAddress();

		// 下面代码是把mac地址拼装成String
		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < mac.length; i++) {
			if (i != 0) {
				sb.append("-");
			}
			// mac[i] & 0xFF 是为了把byte转化为正整数
			String s = Integer.toHexString(mac[i] & 0xFF);
			sb.append(s.length() == 1 ? 0 + s : s);
		}

		// 把字符串所有小写字母改为大写成为正规的mac地址并返回
		return sb.toString().toUpperCase();
	}
	
	@Test
	public void test() {
		LicenseValidate validator = new LicenseValidate();
		assertTrue(validator.validateSign("license.lic"));
	}

}
