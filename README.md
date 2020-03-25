# CSR with Google Cloud KMS (New)

This project is originally from https://github.com/mattes/google-cloud-kms-csr

Thanks for his work, but the library should be updated, also some codes modifiation necessary.

Quick utility tool that creates a CSR cert and signs it with a private key coming from Google Cloud KMS or HSM.
The private key never leaves Google, everyone is happy. The CSR can then be used to get cert from CA.

I would've done it with `openssl`, but there is no Google Cloud KMS engine available. (Sept. 2018) Matt.

I would've done it with `openssl`. (March. 2020) Jung.

## Usage

```
go build -o csr
./csr -project [Project_Name] -region [Region] -ring [KeyRing Name] -key [Key Name] -out out.csr
```

You can verify `my.csr` with:

```
openssl req -text -noout -verify -in my.csr
```

Google's application credentials are used for authenticating with the Google API.
If you haven't done so already, you can set the application default credentials locally with:

```
gcloud auth application-default login
```


## Docs

  * https://cloud.google.com/kms/docs/how-tos
  * https://en.wikipedia.org/wiki/Certificate_signing_request
