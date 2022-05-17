//
// Created by xyz on 2022/5/16.
//

#ifndef STARKWARECRYPTOLIB_FFI_ECKEY_H
#define STARKWARECRYPTOLIB_FFI_ECKEY_H


int SeckeyNegate(const char* private_key, char* out);
int SeckeyTweakAdd(const char* private_key, const char* other_key, char* out);
int SeckeyTweakMul(const char* private_key, const char* other_key, char* out);

int PubkeyParse(const char* pub, int size, char* out);
int PubkeyNegate(const char* pub, char* out);
int PubkeyTweakAdd(const char* pub, const char* other_key, char* out);
int PubkeyTweakMul(const char* pub, const char* private_key, char* out);


#endif //STARKWARECRYPTOLIB_FFI_ECKEY_H
