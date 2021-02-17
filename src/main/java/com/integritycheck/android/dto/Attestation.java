package com.integritycheck.android.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.sql.Timestamp;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Attestation {
    public long timestampMs;
    public String nonce;
    public String apkPackageName;
    public String[] apkCertificateDigestSha256;
    public String apkDigestSha256;
    public String ctsProfileMatch;
    public String basicIntegrity;
    public String evaluationType;
}
