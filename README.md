# ppcrypt
Encrypt/decrypt files or data using private/public key

## Usage
    -g Generate RSA keys
    -e Encrypt data - Public key file name
    -d Decrypt data - Private key file name
    -i Input file name
    -o Output file name

- STDIN/STDOUT is used if input/output file name is not specified
- STDOUT on encryption is in HEX format
- STDIN on decryption is expected in HEX format

## Example
```powershell
.\ppcrypt.exe -g
.\ppcrypt.exe -e public.pem -i input.txt -o input.txt.enc
.\ppcrypt.exe -d private.pem -i input.txt.enc -o input.txt

echo "Hello World!!" | .\ppcrypt.exe -e public.pem | .\ppcrypt.exe -d private.pem
```