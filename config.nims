switch("define", "sslVersion:3")

if defined(useBoringSSL):
  switch("dynlibOverride", "ssl")
  switch("dynlibOverride", "crypto")
  switch("passL", "-Ldeps/boringssl/lib")
  switch("passL", "-lssl")
  switch("passL", "-lcrypto")
  switch("passC", "-Ideps/boringssl/include")
  when defined(macosx):
    switch("passL", "-lc++")
  else:
    switch("passL", "-lstdc++")
elif defined(macosx):
  switch("dynlibOverride", "libssl.3.dylib")
  switch("dynlibOverride", "libcrypto.3.dylib")
  switch("passL", "-L/opt/homebrew/opt/openssl@3/lib")
  switch("passL", "-lssl")
  switch("passL", "-lcrypto")
  switch("passL", "-Wl,-rpath,/opt/homebrew/opt/openssl@3/lib")
elif defined(linux):
  switch("dynlibOverride", "libssl.so")
  switch("dynlibOverride", "libcrypto.so")
  switch("passL", "-lssl")
  switch("passL", "-lcrypto")
