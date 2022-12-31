# Python Bitcoin Address Generation

[***How to use***](#how-to-use-script)

## Bitcoin

[**Bitcoin**](https://bitcoin.org/en/) is a decentralized digital currency that can be transferred on the peer-to-peer bitcoin network. Bitcoin transactions are verified by network nodes through cryptography and recorded in a public distributed ledger called a blockchain. The cryptocurrency was invented in 2008 by an unknown person or group of people using the name Satoshi Nakamoto. [`<sup>`Read more `</sup>`](https://en.wikipedia.org/wiki/bitcoin)

## Bitcoin Addresses

A bitcoin address is a unique identifier that serves as a virtual location where the cryptocurrency can be sent or held. Transactions allow for the transfer of assets between Bitcoin wallets that keep private keys and bitcoin addresses. The private key ensures that the transaction comes from the owner of the wallet. Generating a bitcoin address offline is possible. This code explains how you can generate a bitcoin address step by step. As you see in the figure below, there are some operations while a bitcoin address is generated
`<br>`

## Generate Bitcoin Addresses

[**The Elliptic Curve Digital Signature Algorithm**](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (ECDSA) is used to generate a private-key because public-key cryptography provides bitcoin’s signature principle. Currently Bitcoin uses [**secp256k1**](https://en.bitcoin.it/wiki/Secp256k1) with the ECDSA algorithm.

### Private Key

Formally, a private key for Bitcoin is a series of **32 bytes** (256 bits). Now, there are many ways to record these bytes. It can be a string of 256 ones and zeros (32 * 8 = 256) or 100 dice rolls. It can be represented in various ways (*a binary string, a Base64 string, a WIF key, a mnemonic phrase, or finally, a hex string*). For our purposes, we will use a 64-character-long hex string. A private key might look like this: ``E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262``

### Generating a private key

```python
PrivateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
print("Private Key: ", PrivateKey.to_string().hex())
```

### Public Key

To create a public key from a private one, Bitcoin uses the ECDSA, or Elliptic Curve Digital Signature Algorithm. More specifically, it uses one particular curve called **secp256k1**. A public key is just the x and y co-ordinate of a point on the elliptic curve. It’s usually stored in hexadecimal format.
There are two formats for public keys:

1. *Uncompressed*
   Bitcoin originally used both the x and y coordinate to store the public key. In this uncompressed format, you just place the x and y coordinate next to each other, then prefix the whole thing with an 04 to show that it is an uncompressed public key:`<br>`

``'04' + x-cordinates(32bytes) + y-cordinates(32bytes)`` `<br>`
``'04' + '37c213fs...dfs03fcd' + 'bab2ds3f...8fw3fdb2'``

2. *Compressed*
   However, because the elliptic curve is symmetrical along its x-axis, each x-coordinate will only ever have one of two possible y-coordinates. So in the compressed public key format, we just store the full x coordinate. (along with a prefix that indicates whether the y is even or odd)

- If y is even, it corresponds to one of the points.
- If y is odd, it corresponds to the other.

If y is even, we add `02` as prefix

```
'02' + x-cordinates(32bytes)
'02' + 37c2edc23...gb06e0fc2
```

If y is even, we add `03` as prefix

```
'03' + x-cordinates(32bytes)
'03' + 37c2edc23...gb06e0fc3
```

Generating public key

```python
PublicKey = ecdsaPrivateKey.get_verifying_key().to_string().hex()
print("Public Key: ", PublicKey)
```

- Uncompressed key

```python
PublicKey = '04' +  ecdsaPrivateKey.get_verifying_key().to_string().hex()
print("Public Key: ", PublicKey)
```

- Compressed key

```python
#We use the last byte to check whether y is odd or even.
if int(PublicKey[-1], 16) % 2 == 0:
    PublicKeyCompressed = '02' + PrivateKey.get_verifying_key().to_string()[:32].hex()
else:
    PublicKeyCompressed = '03' + PrivateKey.get_verifying_key().to_string()[:32].hex()
print("Compressed Public Key: ", PublicKeyCompressed)
```

### How to create a public-key hash from public-key?

![public-key-hash](https://github.com/miyurudassanayake/bitcoin-adresses/blob/main/static/hash.png "public key hash")

(The same method is used for compressed and uncompressed keys.)

Apply **SHA256**.

```python
hash256FromPublicKey = hashlib.sha256(binascii.unhexlify(PublicKey)).hexdigest()
print("SHA256(Public Key): ", hash256FromPublicKey)
```

Apply **RIDEMP160**.

```python
ridemp160FromHash256 = hashlib.new('ripemd160', binascii.unhexlify(hash256FromPublicKey))
print("RIDEMP160(SHA256(Public Key)): ", ridemp160FromHash256.hexdigest())
```

### Creating bitcoin address from public-key-hash

Prepend **'00'** as **Network Byte**.

```python
prependNetworkByte = '00' + ridemp160FromHash256.hexdigest()
prependNetworkByteCompressed = '00' + ridemp160FromHash256.hexdigest() + '01'
print("Prepend Network Byte to RIDEMP160(SHA256(Public Key)): ", prependNetworkByte)
print("Prepend Network Byte to RIDEMP160(SHA256(Public Key)) Compressed: ", prependNetworkByte)
```

**SHA256** is used twice to extract 4 bytes from the hash and use them as a checksum.

```python
def getChecksum(hash):
    hash1 = SHA256.new()
    hash1.update(binascii.unhexlify(hash))
    hash2 = SHA256.new()
    hash2.update(binascii.unhexlify(hash1.hexdigest()))
    checksum = hash2.hexdigest()[0:8]
    return checksum
```

Append **Checksum** value.

```python
appendChecksum = prependNetworkByte + getChecksum(prependNetworkByte)
appendChecksumCompressed = prependNetworkByteCompressed + getChecksum(prependNetworkByteCompressed)
print("RIDEMP160(SHA256(Public Key) + Checksum): ", ('00' + ridemp160FromHash256.hexdigest() + appendChecksum)
print("RIDEMP160(SHA256(Public Key) (C) + Checksum): ", ('00' + ridemp160FromHash256.hexdigest() + '01' + appendChecksum)
```

Finally **base58** encode

```python
bitcoinAddress = base58.b58encode(binascii.unhexlify('00'+ridemp160FromHash256.hexdigest()+appendChecksum))
print("Bitcoin Address: ",bitcoinAddress)
bitcoinAddressCompressed = base58.b58encode(binascii.unhexlify('00'+ridemp160FromHash256.hexdigest()+appendChecksumCompressed))
print("Bitcoin Address (c): ",bitcoinAddressCompressed)
```

## Wallet import format (WIF)

A wallet import format (WIF, also known as a *wallet export format*) is a way of encoding a private ECDSA key so as to make it easier to copy. A testing suite is available for encoding and decoding of WIF at: http://gobittest.appspot.com/PrivateKey

### Private key to WIF

1. Take private key.
   ``0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D``
2. Add a 0x80 byte in front of it. Also add a 0x01 byte at the end if the private key will correspond to a [compressed](todo) public key.

```python
PrivateKey = '80' + ecdsaPrivateKey.to_string().hex()
CompressedPrivateKey = '80' + ecdsaPrivateKey.to_string().hex() + '01'
```

3. Add the 4 checksum bytes

```python
PrivateKeyChecksum = getChecksum(PrivateKey)
CompressedPrivateKeyChecksum = getChecksum(CompressedPrivateKey)
WIF = '80' + ecdsaPrivateKey.to_string().hex() + PrivateKeyChecksum
CompressedWIF = '80' + ecdsaPrivateKey.to_string().hex() + '01' + CompressedPrivateKeyChecksum
```

4. Get *binary* from hex and *base58* encode

```python
print("Bitcoin address:", base58.b58encode(WIF.decode('utf-8'))
print("Bitcoin(c) address:", base58.b58encode(CompressedWIF.decode('utf-8'))
```

### WIF to private key

1. Take WIF string ``5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ``
2. Convert into a byte string (decode base58) ``800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D`` (byte string in hex)
3. Drop the last 4 checksum bytes from the byte string. ``800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D`` ~~507A5B8D~~
4. Drop the first byte (it should be 0x80) if the private key corresponded to a [compressed](todo) public key, also drop the last byte (it should be 0x01) ~~80~~ ``0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D``
5. This is the private-key ``0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D``

## How to use script

1. Clone the repository.

```shell
git clone https://github.com/miyurudassanayake/bitcoin-adresses.git
```

3. Install python dependencies.

```shell
pip install -r requirements.txt
```

3. Run the script.

- Create new address

```shell
python3 btcaddress.py
```

- Load from hex private-key

```shell
python3 btcaddress.py <private key (hex)>
```

- Load from WIF private-key

```shell
python3 btcaddress.py <private key (WIF)>
```
