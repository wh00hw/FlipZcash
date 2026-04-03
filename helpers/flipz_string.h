char* flipz_strtok(char* s, const char* delim);
char* flipz_strtok_r(char* s, const char* delim, char** last);

void flipz_btox(const unsigned char* in, int in_len, char* str);
void flipz_xtob(const char* str, unsigned char* out, int out_len);

void flipz_cipher(
    const unsigned char* key_in,
    const unsigned int key_len,
    const char* in,
    char* out,
    const unsigned int io_len);
