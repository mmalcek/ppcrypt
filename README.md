# ppcrypt
Encrypt/decrypt files in stream using private/public key

## Usage
    -g Generate RSA keys
    -e Encrypt data - Public key file name
    -d Decrypt data - Private key file name
    -i Input file name
    -o Output file name

## Example
```powershell
.\ppcrypt.exe -g
.\ppcrypt.exe -e public.pem -i input.txt -o input.txt.enc
.\ppcrypt.exe -d private.pem -i input.txt.enc -o input.txt
```