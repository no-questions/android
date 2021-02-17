package com.integritycheck.android.service;

import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.Base64;
import com.integritycheck.android.dto.Attestation;
import com.integritycheck.android.model.AttestationStatement;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@Service
public class responseService {
    private static final DefaultHostnameVerifier HOSTNAME_VERIFIER = new DefaultHostnameVerifier();
//    private static final String JWT_HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
//    private static String encode(byte[] bytes) {
//        return Base64.encodeBase64String(bytes);
//    }
//    private String hmacSha256(String data, String secret) {
//        try {
//
//            //MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] hash = secret.getBytes(StandardCharsets.UTF_8);//digest.digest(secret.getBytes(StandardCharsets.UTF_8));
//
//            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
//            SecretKeySpec secretKey = new SecretKeySpec(hash, "HmacSHA256");
//            sha256Hmac.init(secretKey);
//
//            byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
//
//            return encode(signedBytes);
//        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
////            Logger.getLogger(JWebToken.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
//            return null;
//        }
//    }

    private AttestationStatement parseAndVerify(String temp) {
        // Parse JSON Web Signature format.
//        String temp = Base64.encodeBase64String((AttestationDto.toString()).getBytes());
//        String signature = hmacSha256(Base64.encodeBase64(JWT_HEADER.getBytes()) + "." + Base64.encodeBase64(AttestationDto.toString().getBytes()), "secret");
//        String jwtToken = Base64.encodeBase64(JWT_HEADER.getBytes()) + "." + Base64.encodeBase64(AttestationDto.toString().getBytes()) + "." + signature;
//        String jwtToken = "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGbERDQ0JIeWdBd0lCQWdJUkFQUWdpNWZxN3EvQkFnQUFBQUNFUGRZd0RRWUpLb1pJaHZjTkFRRUxCUUF3UWpFTE1Ba0dBMVVFQmhNQ1ZWTXhIakFjQmdOVkJBb1RGVWR2YjJkc1pTQlVjblZ6ZENCVFpYSjJhV05sY3pFVE1CRUdBMVVFQXhNS1IxUlRJRU5CSURGUE1UQWVGdzB5TURFeU1UVXhNREUxTlRGYUZ3MHlNVEEyTVRNeE1ERTFOVEJhTUd3eEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxTmIzVnVkR0ZwYmlCV2FXVjNNUk13RVFZRFZRUUtFd3BIYjI5bmJHVWdURXhETVJzd0dRWURWUVFERXhKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNwYmx2WFhpejJrRGkrNFBKL1o1ZGRpdG9FckhyTkZwWWJteGdEM3BxQXA1U2xQeEVwUXNPdzRnWTZtWkJpelUxWWJrdXZxZFkwMUd3QVBOUk5MeEgrVHJPbk1TOGQ1U2FGbXcrMWd1V3Q5a0twajVveUN4dmtkSXBWQmp5bmg3amxQcTZCYndFblpOazBvb01hTW5yRW5Ebmpxb2N0Z095T1hFdmFTWlhwaktSaWRKL2k0dFhGWXU2SUtOakQrQkN1VXVNdGNKRjNvRHpFYVpQdlpnNzU4NFpmSnZHaHI3dlYvMy9VVjdlQlNQZXFBSkxNYWtkRFgyMlE1ekxKMnNUaUs2blhxZGhpUlVma1ZycDdRTFFxTVZCVzd4US82ZzZYdXYxZ2VyYTRjbktzS1hxY1dxUllCUWx4Ujltemw4UmVyQ2FGRXJZK2Q0bnV0anJ6TlNYN0FnTUJBQUdqZ2dKWk1JSUNWVEFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd0V3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVV1RGxJUktOSW5hdkZkYzF0ZkllZCt1WTE4M1F3SHdZRFZSMGpCQmd3Rm9BVW1OSDRiaERyejV2c1lKOFlrQnVnNjMwSi9Tc3daQVlJS3dZQkJRVUhBUUVFV0RCV01DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSd09pOHZiMk56Y0M1d2Eya3VaMjl2Wnk5bmRITXhiekV3S3dZSUt3WUJCUVVITUFLR0gyaDBkSEE2THk5d2Eya3VaMjl2Wnk5bmMzSXlMMGRVVXpGUE1TNWpjblF3SFFZRFZSMFJCQll3RklJU1lYUjBaWE4wTG1GdVpISnZhV1F1WTI5dE1DRUdBMVVkSUFRYU1CZ3dDQVlHWjRFTUFRSUNNQXdHQ2lzR0FRUUIxbmtDQlFNd0x3WURWUjBmQkNnd0pqQWtvQ0tnSUlZZWFIUjBjRG92TDJOeWJDNXdhMmt1WjI5dlp5OUhWRk14VHpFdVkzSnNNSUlCQlFZS0t3WUJCQUhXZVFJRUFnU0I5Z1NCOHdEeEFIY0E3c0NWN28xeVpBK1M0OE81RzhjU28ybHFDWHRMYWhvVU9PWkhzc3Z0eGZrQUFBRjJaaDBhc1FBQUJBTUFTREJHQWlFQW9wL05BemFZV1BWWDFDNld2amF3QkY3Mm5xTjRwNjdLVTdhRzBhd0U4K1FDSVFEVFV6VjJndDYwdmhaZElyb2pLZ1VCb25HY1ZOd1hvdFluREY1V01tRXpBd0IyQVBaY2xDL1JkekFpRkZRWUNEQ1VWbzdqVFJNWk03L2ZEQzhnQzh4TzhXVGpBQUFCZG1ZZEdqNEFBQVFEQUVjd1JRSWdDT1l1ZmVKR0xSMzU5UGpYemI4c0NmWVdtaGlQeHZEZk9zWFlHMzN2d2l3Q0lRQ3lOMHRydHlyTFJHbjNVdUY5SG1KRUNHNEVDTmhLU1c0aUw1VG54NXhBRlRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQVgwMnFKV1RsTlowekZXa3NBMjJsY3A1bEVEV0lZdEc4cXp4cWhOVmZsNlFxUzRFcjFkaFFFbnc3eSt4cDhOTVpSWXZRZVRFeVRGL1FBTnZCYUtUUmlXaWZJOTZBZkJKcDJVUFZMcVpUK3Jwc216UGM1TXpwaERBVW1NRlV3U0JEODAxUkVoUjgvTW5CdFg2aXEwcjc2WlVheVN3dVZ5WGNUWmQwK3cwRkdTbWZVZG1lTUY2Uno5QW9kVXFFMWNEa3NudmI0QzNwUnZOcm9mbXBsSUF2WGdnL3RmR1VWRXVuS3lTMjBnczN4WDROMklRZDRxNlUzRk1oaWN2ejI2T2xrK3krM01xOVNSTkdiZk82dmhib2hEc09nYnNMdzY3aDN3ZlFON2lzYmhKcDRIR2hsdm5mKysxL1ZvdmdmYythUGFVUklCdWFSR1NVK2hEWkxrbXV3Zz09IiwiTUlJRVNqQ0NBektnQXdJQkFnSU5BZU8wbXFHTmlxbUJKV2xRdURBTkJna3Foa2lHOXcwQkFRc0ZBREJNTVNBd0hnWURWUVFMRXhkSGJHOWlZV3hUYVdkdUlGSnZiM1FnUTBFZ0xTQlNNakVUTUJFR0ExVUVDaE1LUjJ4dlltRnNVMmxuYmpFVE1CRUdBMVVFQXhNS1IyeHZZbUZzVTJsbmJqQWVGdzB4TnpBMk1UVXdNREF3TkRKYUZ3MHlNVEV5TVRVd01EQXdOREphTUVJeEN6QUpCZ05WQkFZVEFsVlRNUjR3SEFZRFZRUUtFeFZIYjI5bmJHVWdWSEoxYzNRZ1UyVnlkbWxqWlhNeEV6QVJCZ05WQkFNVENrZFVVeUJEUVNBeFR6RXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEUUdNOUYxSXZOMDV6a1FPOSt0TjFwSVJ2Snp6eU9USFc1RHpFWmhEMmVQQ252VUEwUWsyOEZnSUNmS3FDOUVrc0M0VDJmV0JZay9qQ2ZDM1IzVlpNZFMvZE40WktDRVBaUnJBekRzaUtVRHpScm1CQko1d3VkZ3puZElNWWNMZS9SR0dGbDV5T0RJS2dqRXYvU0pIL1VMK2RFYWx0TjExQm1zSytlUW1NRisrQWN4R05ocjU5cU0vOWlsNzFJMmROOEZHZmNkZHd1YWVqNGJYaHAwTGNRQmJqeE1jSTdKUDBhTTNUNEkrRHNheG1LRnNianphVE5DOXV6cEZsZ09JZzdyUjI1eG95blV4djh2Tm1rcTd6ZFBHSFhreFdZN29HOWorSmtSeUJBQms3WHJKZm91Y0JaRXFGSkpTUGs3WEEwTEtXMFkzejVvejJEMGMxdEpLd0hBZ01CQUFHamdnRXpNSUlCTHpBT0JnTlZIUThCQWY4RUJBTUNBWVl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdIUVlEVlIwT0JCWUVGSmpSK0c0UTY4K2I3R0NmR0pBYm9PdDlDZjByTUI4R0ExVWRJd1FZTUJhQUZKdmlCMWRuSEI3QWFnYmVXYlNhTGQvY0dZWXVNRFVHQ0NzR0FRVUZCd0VCQkNrd0p6QWxCZ2dyQmdFRkJRY3dBWVlaYUhSMGNEb3ZMMjlqYzNBdWNHdHBMbWR2YjJjdlozTnlNakF5QmdOVkhSOEVLekFwTUNlZ0phQWpoaUZvZEhSd09pOHZZM0pzTG5CcmFTNW5iMjluTDJkemNqSXZaM055TWk1amNtd3dQd1lEVlIwZ0JEZ3dOakEwQmdabmdRd0JBZ0l3S2pBb0JnZ3JCZ0VGQlFjQ0FSWWNhSFIwY0hNNkx5OXdhMmt1WjI5dlp5OXlaWEJ2YzJsMGIzSjVMekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBR29BK05ubjc4eTZwUmpkOVhsUVdOYTdIVGdpWi9yM1JOR2ttVW1ZSFBRcTZTY3RpOVBFYWp2d1JUMmlXVEhRcjAyZmVzcU9xQlkyRVRVd2daUStsbHRvTkZ2aHNPOXR2QkNPSWF6cHN3V0M5YUo5eGp1NHRXRFFIOE5WVTZZWlovWHRlRFNHVTlZekpxUGpZOHEzTUR4cnptcWVwQkNmNW84bXcvd0o0YTJHNnh6VXI2RmI2VDhNY0RPMjJQTFJMNnUzTTRUenMzQTJNMWo2YnlrSllpOHdXSVJkQXZLTFdadS9heEJWYnpZbXFtd2ttNXpMU0RXNW5JQUpiRUxDUUNad01INTZ0MkR2cW9meHM2QkJjQ0ZJWlVTcHh1Nng2dGQwVjdTdkpDQ29zaXJTbUlhdGovOWRTU1ZEUWliZXQ4cS83VUs0djRaVU44MGF0blp6MXlnPT0iXX0.eyJub25jZSI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9PSIsInRpbWVzdGFtcE1zIjoxNjEzNTU4Nzk1OTE4LCJhcGtQYWNrYWdlTmFtZSI6ImNvbS5rdW5hbC5zYWZldHluZXRhcGlkZW1vIiwiYXBrRGlnZXN0U2hhMjU2IjoiOW5mSVo2aGRUd3JxcDFnRmdZU0czOVdZOHlkazBKSTVKR2cyU0xxUHE1RT0iLCJjdHNQcm9maWxlTWF0Y2giOnRydWUsImFwa0NlcnRpZmljYXRlRGlnZXN0U2hhMjU2IjpbIkxqcis4MGJ5UlJIZzVmcDZkL3dxRzhoTEVLR2t5UldMNDg2ek9MZkVUV0E9Il0sImJhc2ljSW50ZWdyaXR5Ijp0cnVlLCJldmFsdWF0aW9uVHlwZSI6IkJBU0lDLEhBUkRXQVJFX0JBQ0tFRCJ9.Cv6HlxZqGK57u7kp5ukkLSag9q52yic9ui6oijpDecUR9Qxv-WFmHFvS-JjIyL45PogF5tY_RzIpxXQyspEpDbn7xvxQ4jQIYdRmKSpLPeX3339-_6M1PHckTk37kY9SK3oTXJKkNjN3hD4QRuokoUdQCnnce_Ve4eVp37zmETOTxiyecf4ALriN1J7HyXbRX4DwcCsQQOSEV-L0JU8dmD5IhuDlUP9zcPWGGEYA4ZU-YcqvXOduB52KfSBMEp6HI_x4xyRK0OlOD96qyCHGMnQILlw7exhCMlchepM-oQOXd2hOUtCpSlPrYkqk4y7KWYqSqsyKwW-ZuVTVvZUujQ";
        JsonWebSignature jws;
        try {
            jws = JsonWebSignature.parser(JacksonFactory.getDefaultInstance())
                    .setPayloadClass(AttestationStatement.class).parse(temp);
        } catch (IOException e) {
            System.err.println("Failure: " + temp + " is not valid JWS " +
                    "format.");
            return null;
        }

        // Verify the signature of the JWS and retrieve the signature certificate.
        X509Certificate cert;
        try {
            cert = jws.verifySignature();
            if (cert == null) {
                System.err.println("Failure: Signature verification failed.");
                return null;
            }
        } catch (GeneralSecurityException e) {
            System.err.println(
                    "Failure: Error during cryptographic verification of the JWS signature.");
            return null;
        }

        // Verify the hostname of the certificate.
        if (!verifyHostname("attest.android.com", cert)) {
            System.err.println("Failure: Certificate isn't issued for the hostname attest.android" +
                    ".com.");
            return null;
        }

        // Extract and use the payload data.
        AttestationStatement stmt = (AttestationStatement) jws.getPayload();
        return stmt;
    }
    private static boolean verifyHostname(String hostname, X509Certificate leafCert) {
        try {
            // Check that the hostname matches the certificate. This method throws an exception if
            // the cert could not be verified.
            HOSTNAME_VERIFIER.verify(hostname, leafCert);
            return true;
        } catch (SSLException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean checkValidity(String signedAttestationStatement) {

        AttestationStatement stmt = parseAndVerify(signedAttestationStatement);
        if (stmt == null) {
            System.err.println("Failure: Failed to parse and verify the attestation statement.");
            return false;
        }

        System.out.println("Successfully verified the attestation statement. The content is:");

        System.out.println("Nonce: " + Arrays.toString(stmt.getNonce()));
        System.out.println("Timestamp: " + stmt.getTimestampMs() + " ms");
        System.out.println("APK package name: " + stmt.getApkPackageName());
        System.out.println("APK digest SHA256: " + Arrays.toString(stmt.getApkDigestSha256()));
        System.out.println("APK certificate digest SHA256: " +
                Arrays.deepToString(stmt.getApkCertificateDigestSha256()));
        System.out.println("CTS profile match: " + stmt.isCtsProfileMatch());
        System.out.println("Has basic integrity: " + stmt.hasBasicIntegrity());
        System.out.println("Has BASIC evaluation type: " + stmt.hasBasicEvaluationType());
        System.out.println("Has HARDWARE_BACKED evaluation type: " +
                stmt.hasHardwareBackedEvaluationType());

        System.out.println("\n** This sample only shows how to verify the authenticity of an "
                + "attestation response. Next, you must check that the server response matches the "
                + "request by comparing the nonce, package name, timestamp and digest.");
        return true;
    }
}
