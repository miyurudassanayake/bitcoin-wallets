from ecdsa import SigningKey, SECP256k1
from base58 import b58decode, b58encode
from Crypto.Hash import RIPEMD160, SHA256  # Or hashlib
from sys import argv

# Generate checksum
def getChecksum(hash):
    hash1 = SHA256.new()
    hash1.update(bytes.fromhex(hash))
    hash2 = SHA256.new()
    hash2.update(bytes.fromhex(hash1.hexdigest()))
    checksum = hash2.hexdigest()[0:8]
    return checksum

# Wallet import fromat to hex
def getPrivetKey(WIF: str) -> bytes:
    try:
        decodedValue = b58decode(WIF).hex()
        if decodedValue[:2] == '80':
            if len(decodedValue) == 76 and (decodedValue[-10:-8]) == '01':
                # Compressed
                return bytes.fromhex(decodedValue[2:-10])
            elif len(decodedValue) == 74:
                # Not compressed
                return bytes.fromhex(decodedValue[2:-8])
            else:
                print("[Error] invalid key")
                exit(1)
        else:
            print("[Error] invalid key.")
            exit(1)
    except Exception as e:
        print(e)

def main(privet_key: bytes = None):
    # Check privet key provided or not
    if privet_key == None:
        # If key is not loaded, generate a privet key
        PrivateKey = SigningKey.generate(curve=SECP256k1)
    else:
        # If provided try to validate key (from bytes)
        try:
            PrivateKey = SigningKey.from_string(privet_key, curve=SECP256k1)
        except Exception as e:
            return print(f"[Error] {e}")

    print(f"Private Key: {PrivateKey.to_string().hex()}")

    # Checksum for privet keys (compressed and not compressed)
    checksumPrivetKey = getChecksum('80' + PrivateKey.to_string().hex())
    checksumCompressedPrivetKey = getChecksum('80' + PrivateKey.to_string().hex() + '01')
    print(f"Private Key WIF: {(b58encode(bytes.fromhex('80' + PrivateKey.to_string().hex() + checksumPrivetKey))).decode('utf-8')}")
    print(f"Private Key WIF (c): {(b58encode(bytes.fromhex('80' + PrivateKey.to_string().hex() + '01' + checksumCompressedPrivetKey))).decode('utf-8')}", end="\n\n")

    # Public key from privet key
    PublicKey = '04' + PrivateKey.get_verifying_key().to_string().hex()
    # Compress Public key
    if int(PublicKey[-1], 16) % 2 == 0:
        # If last byte of private key is Even add '02' as prefix
        CompressedPublicKey = '02' + \
            PrivateKey.get_verifying_key().to_string()[:32].hex()
    else:
        # If last byte of private key is Odd add '03' as prefix
        CompressedPublicKey = '03' + \
            PrivateKey.get_verifying_key().to_string()[:32].hex()

    print(f"Public Key: {PublicKey}")
    print(f"Public Key(c): {CompressedPublicKey}", end="\n\n")

    # Hash Public key
    hash256FromPublicKey = SHA256.new()
    hash256FromPublicKey.update(bytes.fromhex(PublicKey))
    ridemp160FromHash256 = RIPEMD160.new()
    ridemp160FromHash256.update(hash256FromPublicKey.digest())

    # Hash compressed Public key
    hash256FromPublicKeyCompressed = SHA256.new()
    hash256FromPublicKeyCompressed.update(bytes.fromhex(CompressedPublicKey))
    ridemp160FromHash256Compressed = RIPEMD160.new()
    ridemp160FromHash256Compressed.update(hash256FromPublicKeyCompressed.digest())

    # Checksums for Public keys (compressed and not compressed)
    checksumPublicKey = getChecksum('00'+ridemp160FromHash256.hexdigest())
    checksumPublicKeyCompressed = getChecksum('00'+ridemp160FromHash256Compressed.hexdigest())

    bitcoinAddress = b58encode(bytes.fromhex('00'+ridemp160FromHash256.hexdigest()+checksumPublicKey))
    bitcoinAddressCompressed = b58encode(bytes.fromhex('00'+ridemp160FromHash256Compressed.hexdigest()+checksumPublicKeyCompressed))
    print("Bitcoin Address    : ", bitcoinAddress.decode('utf8'))
    print("Bitcoin Address (c): ", bitcoinAddressCompressed.decode('utf8'))


if not len(argv) == 1:
    print("[INFO]  Loading BTC wallet from privet-key...")
    if (len(argv[1])) == 52 or len(argv[1]) == 51:
        main(bytes.fromhex(getPrivetKey(argv[1])))

    elif (len(argv[1])) == 64:
        main(bytes.fromhex(argv[1]))

    else:
        print("[ERROR]  Unknown key type!")
else:
    print("[INFO]  Generating a new BTC address...")
    main()

#main("<privet-key-hexadecimal>")
#main(getPrivetKey("<WIF key>"))
