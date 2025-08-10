/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package hwb1;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Applet class
 * 
 * @author <user>
 */
public class FirstApplet extends Applet {
	
	OwnerPIN pin;
	static final byte jmeno [] = {'s', 'a', 'g', 'a', 'd', 'a', 't'};
	byte data [] = new byte [20];
    short dataLength = 0;
    AESKey aes_key;
    AESKey mac_key;
    static final byte aes_key_bytes [] = {
    		0x00,0x01,0x02,0x03,
			0x04,0x05,0x06,0x07,
			0x08,0x09,0x0A,0x0B,
			0x0C,0x0D,0x0E,0x0F,
    		};
    static final byte mac_key_bytes [] = {
    		0x00,0x01,0x02,0x03,
			0x04,0x05,0x06,0x07,
			0x08,0x09,0x0A,0x0B,
			0x0C,0x0D,0x0E,0x0F,
    		};
    Cipher aes;
    Signature mac;
	/**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FirstApplet(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected FirstApplet(byte []bArray, short bOffset, byte bLength) {
    	// check incoming parameter data
        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length
        bOffset = (short)(bOffset + 1);

    	pin = new OwnerPIN((byte)3, (byte)4);
    	pin.update(bArray, bOffset, aLen);
    	aes_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aes_key.setKey(aes_key_bytes, (short)0);
        mac_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        mac_key.setKey(mac_key_bytes, (short)0);
        aes = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    private static final byte INS_GET_NAME = 0x00;
    private static final byte INS_SET_DATA = 0x02;
    private static final byte INS_GET_DATA = 0x04;
    private static final byte INS_VERIFY = 0x20;
    private static final byte INS_AES_ENCRYPT = 0x42;
    private static final byte INS_AES_DECRYPT = 0x44;
    
    public void process(APDU apdu) {
    	if (selectingApplet()){
    		ISOException.throwIt(ISO7816.SW_NO_ERROR);
    	}
    	byte buf [] = apdu.getBuffer();
    	byte cla = buf[ISO7816.OFFSET_CLA];
    	//check if cla is supported
    	if(cla != (byte)0x80) {
    		ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    	}
    	short check_for_bytes = 0;
    	short len = 0;
    	switch(buf[ISO7816.OFFSET_INS]) {
    		case INS_GET_NAME:
    			len = apdu.setOutgoing();
    			if(len > (short)jmeno.length) {
    				len = (short)jmeno.length;
    			}
    			apdu.setOutgoingLength(len);
    			apdu.sendBytesLong(jmeno, (short)0, len);
    			break;
    			
    		case INS_SET_DATA:
    			if(!pin.isValidated()) {
    				ISOException.throwIt((short)0x6300);
    			}
    			len = apdu.setIncomingAndReceive();
    			if(len > data.length) {
    				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    			}
    			Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, data, (short)0, len);
    			dataLength = len;
    			break;
    			
    		case INS_GET_DATA:
    			if(!pin.isValidated()) {
    				ISOException.throwIt((short)0x6300);
    			}
    			len = apdu.setOutgoing();
    			if(len != dataLength) {
                    //incorrect length
    				ISOException.throwIt((short)(ISO7816.SW_CORRECT_LENGTH_00 + dataLength));
    			}
    			apdu.setOutgoingLength(len);
    			apdu.sendBytesLong(data, (short)0, len);
    			break;
    			
    		case INS_VERIFY:
    			len = apdu.setIncomingAndReceive();
    			boolean correct = pin.check(buf, (short)ISO7816.OFFSET_CDATA, (byte)len);
    			if(!correct) {
    				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    			}
    			break;
    			
    		case INS_AES_ENCRYPT:
    			if(!pin.isValidated()) {
    				ISOException.throwIt((short)0x6300);
    			}
    			try {
    				len = apdu.setIncomingAndReceive();
    				check_for_bytes = len;
    			
    				if(len > 64 || len % 16 != 0) {
    					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); //0x6700
    				}
    			
    				aes.init(aes_key, Cipher.MODE_ENCRYPT);
    				aes.doFinal(buf, (short)ISO7816.OFFSET_CDATA, len, buf, (short)ISO7816.OFFSET_CDATA);
    			}catch(CryptoException e) {
    				ISOException.throwIt(e.getReason());
    			}
    			
    			try {
    				mac.init(mac_key, Signature.MODE_SIGN);
        		    mac.sign(buf, (short)ISO7816.OFFSET_CDATA, len, buf, (short)(ISO7816.OFFSET_CDATA + len));
    			}catch(CryptoException e) {
    				ISOException.throwIt(e.getReason());
    			}
    		    len = apdu.setOutgoing();
    		    if(len < check_for_bytes) {
    		    	len = (short)(check_for_bytes + 16);
    		    }
    		    apdu.setOutgoingLength(len);
    		    apdu.sendBytesLong(buf, (short)(ISO7816.OFFSET_CDATA), len);
    		    break;
    		case INS_AES_DECRYPT:
    			
    			if(!pin.isValidated()) {
    				ISOException.throwIt((short)0x6300);
    			}
    			
    			try {
    				if((len % 16 != 0) || (len > 80) || (len == 16)) {
    					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    				}
    				len = apdu.setIncomingAndReceive();
    				check_for_bytes = len;
    				mac.init(mac_key, Signature.MODE_VERIFY);
    				if( ! mac.verify(buf, (short)(ISO7816.OFFSET_CDATA), 
    					(short)(len - 16), buf, 
    					(short)(ISO7816.OFFSET_CDATA + len - 16) , (short)16)) {
    					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    				}
    			}catch(CryptoException output) {
    				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    			}
    			
    			try {
    				aes.init(aes_key, Cipher.MODE_DECRYPT);
    				aes.doFinal(buf, (short)(ISO7816.OFFSET_CDATA), len, buf, (short)(ISO7816.OFFSET_CDATA));
    			}catch(CryptoException output) {
    				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    			}
    			
    			len = apdu.setOutgoing();
    			if(len < (short)(check_for_bytes - 16)) {
    				len = (short)(check_for_bytes - 16);
    			}
    			apdu.setOutgoingLength(len);
    			apdu.sendBytesLong(buf, (short)(ISO7816.OFFSET_CDATA), len);
    			break;
    		default:
    			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    			break;
    			
    	}
    }
    
    public boolean select() {
    	if(pin.getTriesRemaining() == 0) {
    		return false;
    	}
    	return true;
    }
}
