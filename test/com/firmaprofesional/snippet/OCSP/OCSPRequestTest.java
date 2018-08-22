package com.firmaprofesional.snippet.OCSP;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author DevTeam
 */
public class OCSPRequestTest {

    private OCSPRequest instance;
    /**
     * Firmaprofesional's CA to test: CUALIFICADOS
     * http://crl.firmaprofesional.com/cualificados.crt 
     * CN = AC Firmaprofesional - CUALIFICADOS 
     * SERIALNUMBER = A62634068 
     * OU = Certificados Cualificados 
     * O = Firmaprofesional S.A. 
     * C = ES
     * 
     * Raw PEM without header and footer
     */
    String caToCheck = "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";

    @Before
    public void setUp() {
        instance = new OCSPRequest(caToCheck);
    }

    /**
     * Test of checkSerialNumber method, of class OCSPRequest.
     *
     */
    @Test
    public void testCheckSerialNumberValid() {
        System.out.println("checkSerialNumber valid");
        String serialNumberToCheck = "0572DF3C6D1F6892";
        String expResult = "OK";
        String result = instance.checkSerialNumber(serialNumberToCheck);
        assertEquals(expResult, result);
    }

    /**
     * Test of checkSerialNumber method, of class OCSPRequest.
     */
    @Test
    public void testCheckSerialNumberRevoked() {
        System.out.println("checkSerialNumber revoked");
        String serialNumberToCheck = "2E5A62D355087257";
        String expResult = "REVOKED";
        String result = instance.checkSerialNumber(serialNumberToCheck);
        assertEquals(expResult, result);
    }

    /**
     * Test of checkSerialNumber method, of class OCSPRequest.
     * Using GET method
     */
    @Test
    public void testCheckSerialNumberValidGet() {
        System.out.println("checkSerialNumber valid");
        String serialNumberToCheck = "0572DF3C6D1F6892";
        String expResult = "OK";
        instance = new OCSPRequest(caToCheck, "GET");
        String result = instance.checkSerialNumber(serialNumberToCheck);
        assertEquals(expResult, result);
    }
}
