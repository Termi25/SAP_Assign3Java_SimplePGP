You are expecting an important message regarding your SAP exam.
You have received 3 messages (see the SAPExamSubject text files), but you know that Vader is trying to spam you with false information.
Each message has an associated SHA512withRSA signature (see the corresponding .signature files)

Because you have your professor RSA public key (see the SimplePGP_ISM.cer X509 file) you can verify the messages and  identify the original one.

To acknowledge the message receipt you need to send an encrypted message to your professor.
The message must contain your name and you can add any question you have about the exam.

In order to send the encrypted response you must:

1. generate a secret random AES 128 bit key
2. use the secret key to encrypt in ECB mode your response
3. generate your own RSA public-private pair using keytool (the certificate owner must be you and not ISM)
4. encrypt the AES key with the professor public key
5. send the encrypted AES key, your encrypted response and your public certificate
6. compute a digital signature for the response file and save it in a signature.ds binary file
