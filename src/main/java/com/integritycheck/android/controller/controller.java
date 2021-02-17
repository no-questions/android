package com.integritycheck.android.controller;

import com.integritycheck.android.dto.Attestation;
import com.integritycheck.android.service.responseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value="/api/v2")
public class controller {
    @Autowired
    responseService responseservice;
    @PostMapping("/validateresponse")
    public boolean validateResponse(@RequestHeader("attestation") String signedAttestationStatement){
        return responseservice.checkValidity(signedAttestationStatement);
    }

}
