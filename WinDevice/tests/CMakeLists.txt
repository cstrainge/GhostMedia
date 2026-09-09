add_executable(GhostMediaWinCryptoProviderTests
    crypto_provider_tests.cpp)

target_link_libraries(GhostMediaWinCryptoProviderTests PRIVATE
    GhostMediaWinSecurity
    OpenSSL::Crypto)

target_compile_features(GhostMediaWinCryptoProviderTests PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(GhostMediaWinCryptoProviderTests PRIVATE /W4 /permissive-)
else()
    target_compile_options(GhostMediaWinCryptoProviderTests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME win_crypto_provider_tests COMMAND GhostMediaWinCryptoProviderTests)