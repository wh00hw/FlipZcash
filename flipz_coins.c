#include <flipz_coins.h>

// bip44_coin, xprv_version, xpub_version, addr_version, wif_version, addr_format
const uint32_t COIN_INFO_ARRAY[NUM_COINS][COIN_INFO_SIZE] = {
    {133, 0x00, 0x00, 0x00, 0x00, CoinTypeZECOrchard},
    {1, 0x00, 0x00, 0x00, 0x00, CoinTypeZECOrchardTest},
};

// coin_label, derivation_path, coin_name, static_prefix ("_" for none)
const char* COIN_TEXT_ARRAY[NUM_COINS][COIN_TEXT_SIZE] = {
    {"ZEC", "m_o/32'/133'/0'", "zcash:", "u"},
    {"tZEC", "m_o/32'/1'/0'", "zcash:", "utest"}};
