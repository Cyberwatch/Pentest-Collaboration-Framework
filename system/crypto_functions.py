import uuid, random, string, hashlib
import bcrypt
from passlib.hash import md5_crypt, des_crypt, sha512_crypt, sha256_crypt, \
    nthash, lmhash
import base64


def gen_uuid():
    return str(uuid.uuid4())


def random_string(string_length=10):
    letters = string.ascii_lowercase + '0123456789'
    return ''.join(random.choice(letters) for i in range(string_length))


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('charmap')


def check_hash(pwd_hash, password):
    return bcrypt.hashpw(password.encode('utf-8'),
                         pwd_hash.encode('charmap')) == pwd_hash.encode(
        'charmap')


def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def md5_hex_str(cleartext: string) -> string:
    return hashlib.md5(cleartext.encode('utf-8')).hexdigest()


def sha1_hex_str(cleartext: string) -> string:
    return hashlib.sha1(cleartext.encode('utf-8')).hexdigest()


def sha256_hex_str(cleartext: string) -> string:
    return hashlib.sha256(cleartext.encode('utf-8')).hexdigest()


def sha512_hex_str(cleartext: string) -> string:
    return hashlib.sha512(cleartext.encode('utf-8')).hexdigest()


def des_crypt_str(cleartext: string, salt: string) -> string:
    return des_crypt.hash(cleartext, salt=salt)


def md5_crypt_str(cleartext: string, salt: string) -> string:
    return md5_crypt.hash(cleartext, salt=salt)


def sha1_crypt_str(cleartext: string, salt: string) -> string:
    return md5_crypt.hash(cleartext, salt=salt)


def sha256_crypt_str(cleartext: string, salt: string) -> string:
    return sha256_crypt.encrypt(cleartext, salt=salt, rounds=5000)


def sha512_crypt_str(cleartext: string, salt: string) -> string:
    return sha512_crypt.encrypt(cleartext, salt=salt, rounds=5000)


def nt_hex_str(cleartext: string) -> string:
    return nthash.encrypt(cleartext)


def lm_hex_str(cleartext: string) -> string:
    return lmhash.encrypt(cleartext)


def rabbitmq_md5_str(cleartext: string, salt: bytes) -> string:
    enc_str = salt + cleartext.encode('utf-8')

    hash_md5 = hashlib.md5(enc_str).digest()
    hash_base64 = base64.b64encode(salt + hash_md5)

    return hash_base64.decode('charmap')
