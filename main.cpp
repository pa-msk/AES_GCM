#include <openssl/evp.h>
#include "Hexdump.h"

int GCMEncrypt(const unsigned char* plainText,
               int plainTextLen,
               const unsigned char* aad,
               int aadLen,
               const unsigned char* key,
               const unsigned char* IV,
               int IVLen,
               unsigned char* cipherText,
               unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLen, NULL);
    
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, IV);
    
    int len = 0;
    
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aadLen);
    
    EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen);
    
    int encryptedLen = len;
    
    EVP_EncryptFinal_ex(ctx, cipherText + len, &len);
    encryptedLen += len;
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return encryptedLen;
}

int GCMDecrypt(const unsigned char* cipherText,
               int cipherTextLen,
               const unsigned char* aad,
               int aadLen,
               unsigned char* tag,
               const unsigned char* key,
               const unsigned char* IV,
               int IVLen,
               unsigned char* plainText)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLen, NULL);
    
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, IV);
    
    int len = 0;
    
    EVP_DecryptUpdate(ctx, NULL, &len, aad, aadLen);
    
    EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen);
    
    int plainTextLen = len;
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    
    int result = EVP_DecryptFinal_ex(ctx, plainText + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if(result > 0)
    {
        plainTextLen += len;
        return plainTextLen;
    }

    return -1;
}

int main(int argc, const char* argv[])
{
    const unsigned char* plainText = (const unsigned char*)("Im a secret message!");
    int plainTextLen = 20;
    
    printf("Plain text input:\n");
    HexDump(plainText, plainTextLen);
    
    //256 bit key
    const unsigned char* key = (const unsigned char*)("12345678901234567890123456789012");
    
    const unsigned char* aad = (const unsigned char*)("1234");
    int aadLen = 4;
    
    unsigned char* IV = (unsigned char*)("123456789012");
    int IVLen = 12;
    
    unsigned char encryptedText[128] = {0};
    unsigned char tag[16] = {0};
    
    int encryptedLen = GCMEncrypt(plainText, plainTextLen, aad, aadLen, key, IV, IVLen, encryptedText, tag);

    printf("Encrypted message:\n");
    HexDump(encryptedText, encryptedLen);
    
    unsigned char decryptedText[128] = {0};
    int decryptedLen = GCMDecrypt(encryptedText, encryptedLen, aad, aadLen, tag, key, IV, IVLen, decryptedText);
  
    printf("Decrypted text: %s\n", decryptedText);
    
    if(decryptedLen > -1)
    {
        HexDump(decryptedText, decryptedLen);
    }
    else
    {
        printf("Decryption error\n");
    }
}
