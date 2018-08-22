package com.firmaprofesional.snippet.OCSP;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * @author DevTeam
 */
public class OCSPRequest {

    /**
     * Firmaprofesional public ocsp service. 
     * Can change it if you need it using setOcspServer. This is a free OCSP
     * service and could not be 24/7 service
     * If you need a more reliable solution, please contact our sales team
     */
    static String ocspServer = "http://ocsp.firmaprofesional.com";

    private final String ca;
    private final String method;
    private final String username;
    private final String password;
    private static final Logger LOG = Logger.getLogger(OCSPRequest.class.getName());

    
    /**
     * OCSP request will be send using POST without authentication
     * 
     * @param caToCheck CA provided in raw PEM format
     */
    public OCSPRequest(String caToCheck) {
        ca = caToCheck;
        username = null;
        password = null;
        method = "POST";
    }
    
    /**
     * OCSP request will be send using POST|GET without authentication
     * 
     * @param caToCheck CA provided in raw PEM format
     * @param httpMethod POST|GET
     */
    public OCSPRequest(String caToCheck, String httpMethod) {
        ca = caToCheck;
        username = null;
        password = null;
        method = httpMethod;
    }
    
    /**
     * OCSP request will be send using POST with authentication
     * 
     * @param caToCheck CA provided in raw PEM format
     * @param authUsername
     * @param authPassword 
     */
    public OCSPRequest(String caToCheck, String authUsername, String authPassword) {
        ca = caToCheck;
        username = authUsername;
        password = authPassword;
        method = "POST";
    }
    
    /**
     * Check Serial number against ocsp server with CA provided
     * Could return:
     * - OK
     * - REV
     * - UKNW
     * @param serialNumberToCheck
     * @return String
     */
    public String checkSerialNumber(String serialNumberToCheck) {
        
        String checkedResponse = null;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        try {
            BigInteger serialNumber = new BigInteger(serialNumberToCheck, 16);
            
            LOG.info("Generating and sending OCSPRequest");
            OCSPResp response = getOCSPResponse(serialNumber);
            
            LOG.info("Validating OCSPResponse");
            checkedResponse = validateOCSPResponse(response);
            
            LOG.info("OCSPResponse validated");
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
        
        return checkedResponse;
    }
    
    /**
     * Generate the request and send it throw the method choosed
     * @param serialNumber
     * @return OCSPResp
     * @throws Exception 
     */
    private OCSPResp getOCSPResponse (BigInteger serialNumber) throws Exception {
        
        OCSPReq request = generateOCSPRequest(serialNumber);
        OCSPResp response = null;
        switch (method) {
            case "POST":
                response = sendPost(request.getEncoded());
                break;
            case "GET":
                 response = sendGet(request.getEncoded());
                break;
            default:
                throw new Exception("Method not allowed");
        }
        return response;
    }
    
    /**
     * Validate and check the OCSP Response and returns a string with the
     * validation of the serialnumber UKNW|OK|REVOKED
     *
     * @param response
     * @return String
     * @throws Exception 
     */
    private String validateOCSPResponse(OCSPResp response) throws Exception {

        String status = "UKNW";
        switch (response.getStatus()) {
            case 0:
                BasicOCSPResp ocspResponseData = (BasicOCSPResp) response.getResponseObject();
                SingleResp[] responses = ocspResponseData.getResponses();
                for (SingleResp response1 : responses) {
                    if (response1.getCertStatus() == null) {
                        status = "OK";
                    } else if (response1.getCertStatus() instanceof RevokedStatus) {
                        status = "REVOKED";
                    }
                    LOG.log(Level.INFO, "OCSP response code: {0}", status);
                }
                break;
            case 1:
                LOG.log(Level.SEVERE, "Malformed request. OCSP response code: {0}", response.getStatus());
                throw new Exception("Malformed request");
            default:
                LOG.log(Level.SEVERE, "Uncaught error. OCSP response code: {0}", response.getStatus());
                throw new Exception("Uncaught error");
        }
        return status;
    }
    
    /**
     * Generate OCSPReq with serialnumber and CA provided
     * 
     * @param serial
     * @return
     * @throws Exception 
     */
    private OCSPReq generateOCSPRequest(BigInteger serial) throws Exception {

        OCSPReq request = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(ca));
            X509Certificate issuerCert = (X509Certificate) certFactory.generateCertificate(in);
    
            JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
            DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
            DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);

            LOG.log(Level.INFO, "CA subject: {0}", issuerCert.getIssuerX500Principal().getName("CANONICAL"));
            LOG.log(Level.INFO, "Serial number: {0}", serial);
            
            // Generate the id for the certificate we are looking for
            CertificateID id = new CertificateID(digestCalculator, new JcaX509CertificateHolder(issuerCert), serial);
            OCSPReqBuilder ocspGen = new OCSPReqBuilder();
            ocspGen.addRequest(id);

            request = ocspGen.build();
        } catch (CertificateException | OCSPException | OperatorCreationException e) {
            System.out.println("Error generateOCSPRequest:" + e.getMessage());
        }
        
        return request;
    }
    
    /**
     * Send ocsp request using POST
     * @param request
     * @return
     * @throws IOException 
     */
    private OCSPResp sendPost(byte[] request) throws IOException {

        URL url = new URL(ocspServer);
        
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setRequestProperty("Content-Length", "4096");
        
        if (username != null && password != null) {
            if (!username.isEmpty() && !password.isEmpty()) {
                String auth = username + ":" + password;
                connection.setRequestProperty("Authorization", "Basic " + DatatypeConverter.printBase64Binary(auth.getBytes()));
            }
        }
            
        OutputStream output = connection.getOutputStream();
        output.write(request);
        
        InputStream input = connection.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead = 0;
        while ((bytesRead = input.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, bytesRead);
        }
        
        LOG.log(Level.INFO, "Http response code: {0}", connection.getResponseCode());
        byte[] respBytes = baos.toByteArray();
        
        return new OCSPResp(respBytes);
    }
    
    /**
     * Send ocsp request using GET
     * 
     * @param request
     * @return
     * @throws IOException 
     */
    private OCSPResp sendGet(byte[] request) throws IOException {
        
        URL url = new URL(ocspServer + "/" + DatatypeConverter.printBase64Binary(request));
        
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int byteRead;
        InputStream is = connection.getInputStream();
        while ((byteRead = is.read()) != -1) {
            baos.write(byteRead);
        }
        is.close();
        byte[] respBytes = baos.toByteArray();
        
        return new OCSPResp(respBytes);
    }
    
    /**
     * Set the ocsp server
     * @param server 
     */
    public void setOcspServer(String server) {
        ocspServer = server;
    }
}
