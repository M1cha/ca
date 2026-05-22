# CA

## Dependencies

```bash
pacman -S libp11 opensc
```

## Usage

```bash
RUST_LOG=debug cargo run --release -- config.ron --exclude-tag lxd-2
```

## Create keypair on Nitro key

```bash
pkcs11-tool -r --type cert --label CA-mqtt -o ca-mqtt.der
```

## Generate CA certificate

```bash
OPENSSL_CONF=$PWD/openssl.conf openssl req -new -x509 -engine pkcs11 -key 'pkcs11:object=CA-mqtt;type=private' -keyform engine -out ca-mqtt.pem -text -days 3650
```
