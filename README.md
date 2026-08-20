# cps-http

HTTP/1.1, HTTP/2 and HTTP/3 clients and servers for the CPS Nim runtime.

## Install

```sh
nimble install https://github.com/gabearro/cps-http@#v1.0.0
```

```nim
import cps/httpclient
```

Dependencies are resolved automatically by Nimble: `cps-runtime`, `cps-tls`, `cps-quic`.

## Development

```sh
nimble install -d -y
nimble test
```

This repository was extracted from [gabearro/cps-runtime](https://github.com/gabearro/cps-runtime) with its relevant Git history preserved.

## License

MIT

