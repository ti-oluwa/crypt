## dcrypt

Use RSA + Fernet encryption to encrypt and decrypt text and Python objects.

## Installation

Install with pip:

```bash
pip install dcrypt
```

## Usage

`dcrypt` contains three classes that can be used for encryption and decryption:

- `TextCrypt`: Encrypts and decrypts text.
- `ObjectCrypt`: Encrypts and decrypts text and Python objects (using `pickle`).
- `JSONCrypt`: `ObjectCrypt` that encrypts into a JSON parsable format.

Let's start by encrypting some text we want to keep secret:

```python
import dcrypt

# First, we create a cryptkey
cryptkey = dcrypt.CryptKey()

# Then, we create a TextCrypt object with the key
text_crypt = dcrypt.TextCrypt(key=cryptkey)

# Now, we can encrypt some text
encrypted_text = text_crypt.encrypt("This is a secret message!")
print(encrypted_text)

# And decrypt it again
decrypted_text = text_crypt.decrypt(encrypted_text)
print(decrypted_text)
```

How about encrypting Python objects?

```python
# We can use our existing cryptkey

# Create an ObjectCrypt object with the key
object_crypt = dcrypt.ObjectCrypt(key=cryptkey)

# Encrypt a Python object
my_secrets = {
    "passcode": 1234,
    "password": "password123",
}

encrypted_object = object_crypt.encrypt(my_secrets)
print(encrypted_object)

# The Output would be something like:
# {
#   "passcode": "gAAAAABgJ0Z...",
#   "password": "gAAAAABgJ0Z...",
# }
```

You could also decide to use the object crypt to encrypt text too.

Okay! Let's assume that we want to store `my_secrets` in JSON format. It would be nice if `my_secrets` is encrypted in a format that is JSON serializable. We can do this by using the `JSONCrypt` class:

```python
# Let's add a tuple of emails to our secrets
my_secrets["emails"] = ("user@host.com", "abc@xyz.com")

# With JSONCrypt
json_crypt = dcrypt.JSONCrypt(key=cryptkey)
encrypted_secrets = json_crypt.encrypt(my_secrets)

# Let's decrypt it again
decrypted_secrets = json_crypt.decrypt(encrypted_secrets)

# Just to be sure, let's check that the decrypted secrets are the same as the original secrets
assert decrypted_secrets == my_secrets

# Oops! We get an error:
# AssertionError
# Why? Because the tuple was converted to a list when we encrypted it.
# So take note of this when using JSONCrypt.
```

### `CryptKey`

A cryptkey is simply a key that is used to encrypt and decrypt data.

Let's create a cryptkey:

```python
import dcrypt

cryptkey = dcrypt.CryptKey()
```

Hmm... that was easy. But what actually is a cryptkey? A cryptkey is an object containing a signature used to encrypt and decrypt data. Wondering what the signature is? A cryptkey signature contains four things:

- A rsa public key
- A rsa private key
- An encrypted master key (Fernet key)
- The hash method used to sign and verify the master key

The rsa keys are used to encrypt and decrypt the master key. The master key is used to encrypt and decrypt data. The rsa keys are generated using the `rsa` library. The master key is generated using the `cryptography` library's `Fernet` class.

What if we want stronger encryption? We can specify the keys signature strength

```python
cryptkey = dcrypt.CryptKey(signature_strength=2)
# The default is 1. But we can specify 2 or 3 for stronger encryption.
# The caveat is that the higher the signature strength, the longer it takes to generate the cryptkey.
```

We can also specify the hash method used to sign and verify the master key

```python
cryptkey = dcrypt.CryptKey(hash_algorithm="SHA-512")

# See `dcrypt.signature.SUPPORTED_HASH_ALGORITHMS` for a list of supported hash methods.
```

### Saving and Loading CryptKeys

I know, I know. You want to save your cryptkey so you can use it later. You can do this by saving the cryptkey's signature to a file. Let's see how:

```python
import dcrypt

# Shinny new cryptkey
cryptkey = dcrypt.CryptKey()

# Now, let's save it
cryptkey.signature.dump("./secrets_folder/cryptkey.json")

# Yes! We saved it. Now, let's load our key signature back and recreate our cryptkey
signature = dcrypt.Signature.load("./secrets_folder/cryptkey.json")
cryptkey = dcrypt.CryptKey(signature=signature)

# Yay! We have our cryptkey back.
```

> Another reason why you may want to save your key signature is to remove the overhead of generating a new cryptkey every time you want to encrypt or decrypt data. Especially when the signature strength is maxed out(3). You can just load the signature from a file and use it to create a new cryptkey.

### Let's talk about cryptkey signatures

The cryptkey signature is a NamedTuple which contains...? Right! A public key, a private key, an encrypted master key and a hash method.

The cool thing about cryptkey signatures is that once created, they cannot be modified. So we can access the public key, private key, encrypted master key and hash method without worrying about them being modified.

Let's see how we can use cryptkey signatures:

```python
import dcrypt

signature = dcrypt.CryptKey.make_signature()
# Yes! we use the `make_signature` classmethod to create a cryptkey signature.

# Now, let's access the public key
public_key = signature.pub_key

# What about the hash method?
hash_method = signature.hash_method

# And the encrypted master key?
encrypted_master_key = signature.enc_master_key
```

There are two types of cryptkey signatures:

- `Signature`
- `CommonSignature`

What are the differences between them? Let's start with the `CommonSignature`.
A `CommonSignature` is a cryptkey signature whose values are all strings. This means that it can be easily serialized and deserialized. This is the type of signature that is saved to a file when we use the `dump` method.

Unlike the `CommonSignature`, a `Signature` is a cryptkey signature whose values are not all strings. Some are byte type. This means that it cannot be easily serialized and deserialized. This is the type of signature that is used to create a cryptkey.

However, we can convert a `Signature` to a `CommonSignature` and vice versa:

```python
import dcrypt

# Let's create a cryptkey signature
signature = dcrypt.CryptKey.make_signature()

# Now, let's convert it to a common signature
common_signature = signature.common()

# And back to a signature
signature = dcrypt.Signature.from_common(common_signature)
```

Easy, right? But why do we need to convert a signature to a common signature? Well, we need to do this when we want to save a cryptkey signature to a file. We can't save a `Signature` to a file. We can only save a `CommonSignature` to a file.

Another use case is if we need to send a cryptkey signature over a network, we need to convert it to a common signature first and then convert it back to a signature when we receive it.

```python
import dcrypt
import requests

# Let's create a cryptkey signature
signature = dcrypt.CryptKey.make_signature()

# Now, let's convert it to a common signature
common_signature = signature.common()

# Let's send it over a network
requests.post("https://example.com", json=common_signature.json())

# Now, let's receive it
common_signature_as_json = requests.get("https://example.com").json()

# Construct a common signature from the json
common_signature = dcrypt.CommonSignature(**common_signature_as_json)

# And convert it back to a signature
signature = dcrypt.Signature.from_common(common_signature)
# Easy peasy!
```

If you noticed, we converted the common signature to json before sending it over the network. You do this using the `json` method of the `CommonSignature` class.

### Encrypting function output

Say you have a method in a class called `Human` which returns the contact information of the human which will be sent over a network. You may want to encrypt the result of the method before sending it. How do you do this?

First let's define our `Human` class:

```python
from dataclasses import dataclass

@dataclass
class Human:
    name: str
    gender: str
    email: str
    phonenumber: str
    address: str
    ...

    def get_contact_info(self):
        return {
            "email": self.email,
            "phonenumber": self.phonenumber,
        }
```

Now, let's create a cryptkey and an `ObjectCrypt` object:

```python
import dcrypt

# Create a cryptkey
cryptkey = dcrypt.CryptKey()

# Create an ObjectCrypt object
object_crypt = dcrypt.ObjectCrypt(key=cryptkey)

# Let save the cryptkey signature to a file
cryptkey.signature.dump("./secrets_folder/cryptkey.json")
```

All that's left is to decorate the `get_contact_info` method with the object crypt we just created:

```python

class Human:
    ...

    @object_crypt
    def get_contact_info(self):
        return {
            "email": self.email,
            "phonenumber": self.phonenumber,
        }
```

That's it! Now, the result of the `get_contact_info` method will be encrypted before it is returned and yes you can decrypt it with the same object crypt or create a new object crypt with the already saved cryptkey signature.

```python
tolu = Human(
    name="Tolu",
    gender="Male",
    email="tioluwa.dev@gmail.com",
    phonenumber="08012345678",
    address="Lagos, Nigeria."
)

# Let's get his contact info
encrypted_contact_info = tolu.get_contact_info()

# The output would be something like:
# {
#   "email": "gAAAAABgJ0Z...",
#   "phonenumber": "gAAAAABgJ0Z...",
# }

# Now, let's decrypt it
signature = dcrypt.Signature.load("./secrets_folder/cryptkey.json")
new_cryptkey = dcrypt.CryptKey(signature=signature)
new_object_crypt = dcrypt.ObjectCrypt(key=new_cryptkey)
decrypted_contact_info = new_object_crypt.decrypt(contact_info)

# The output should be:
# {
#   "email": "tioluwa.dev@gmail",
#   "phonenumber": "08012345678",
# }
```

You are now ready to use `dcrypt` to encrypt and decrypt your data. Goodluck!

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Testing

To run the tests, simply run the following command in the root directory of your cloned repository:

```bash
python -m unittest discover tests "test_*.py"
```
