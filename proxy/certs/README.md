Put Apple's App Attestation Root CA here as `Apple_App_Attestation_Root_CA.pem`.

It's listed on Apple's Private PKI page (https://www.apple.com/certificateauthority/private/)
as "Apple App Attestation Root CA". From the `proxy` folder:

    curl -o certs/Apple_App_Attestation_Root_CA.pem \
      https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem

Check it with `openssl x509 -in certs/Apple_App_Attestation_Root_CA.pem -noout -subject -dates`.
Don't take it from a third-party source.

