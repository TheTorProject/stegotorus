/* Copyright 2011 Nick Mathewson, George Kadianakis
 * Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */
#ifndef CRYPT_H
#define CRYPT_H

const size_t AES_BLOCK_LEN = 16;
const size_t GCM_TAG_LEN   = 16;
const size_t SHA256_LEN    = 32;
const size_t EC_P224_LEN   = 28;
const size_t MKE_MSG_LEN   = 21;

/**
 * Initialize cryptography library.  Must be called before anything that
 * uses any of the APIs below.
 */
void init_crypto();

/**
 * Tear down cryptography library.
 */
void free_crypto();

/**
 * Report a cryptography failure.
 * @msg should describe the operation that failed.
 * Always returns -1; this allows you to write
 * if (some operation failed)
 *   return log_crypto_warn("some operation");
 */
int log_crypto_warn(const char *msg);

/**
 * Report a cryptography failure which is a fatal error.
 * @msg should describe the operation that failed.
 * Does not return.
 */
void ATTR_NORETURN log_crypto_abort(const char *msg);

struct key_generator;

struct ecb_encryptor
{
  /** Return a new AES/ECB encryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static ecb_encryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/ECB encryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static ecb_encryptor *create(key_generator *gen, size_t keylen);

  /** Return a new AES/ECB encryption state that doesn't actually
      encrypt anything -- it just copies its input to its output.
      For testing purposes only.  */
  static ecb_encryptor *create_noop();

  /** Encrypt exactly AES_BLOCK_LEN bytes of data in the buffer 'in' and
      write the result to 'out'.  */
  virtual void encrypt(uint8_t *out, const uint8_t *in) = 0;

  virtual ~ecb_encryptor();
protected:
  ecb_encryptor() {}
private:
  ecb_encryptor(const ecb_encryptor&);
  ecb_encryptor& operator=(const ecb_encryptor&);
};

struct ecb_decryptor
{
  /** Return a new AES/ECB decryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static ecb_decryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/ECB decryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static ecb_decryptor *create(key_generator *gen, size_t keylen);

  /** Return a new AES/ECB decryption state that doesn't actually
      decrypt anything -- it just copies its input to its output.
      For testing purposes only.  */
  static ecb_decryptor *create_noop();

  /** Decrypt exactly AES_BLOCK_LEN bytes of data in the buffer 'in' and
      write the result to 'out'.  */
  virtual void decrypt(uint8_t *out, const uint8_t *in) = 0;

  virtual ~ecb_decryptor();
protected:
  ecb_decryptor() {}
private:
  ecb_decryptor(const ecb_decryptor&) DELETE_METHOD;
  ecb_decryptor& operator=(const ecb_decryptor&) DELETE_METHOD;
};


struct gcm_encryptor
{
  /** Return a new AES/GCM encryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static gcm_encryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/GCM encryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static gcm_encryptor *create(key_generator *gen, size_t keylen);

  /** Return a new AES/GCM encryption state that doesn't actually
      encrypt anything -- it just copies its input to its output.
      For testing purposes only.  */
  static gcm_encryptor *create_noop();

  /** Encrypt 'inlen' bytes of data in the buffer 'in', writing the
      result plus an authentication tag to the buffer 'out', whose
      length must be at least 'inlen'+16 bytes.  Use 'nonce'
      (of length 'nlen') as the encryption nonce; 'nlen' must be at
      least 12 bytes.  */
  virtual void encrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                       const uint8_t *nonce, size_t nlen) = 0;

  virtual ~gcm_encryptor();
protected:
  gcm_encryptor() {}
private:
  gcm_encryptor(const gcm_encryptor&);
  gcm_encryptor& operator=(const gcm_encryptor&);
};

struct gcm_decryptor
{
  /** Return a new AES/GCM decryption state using 'key' (of length 'keylen')
      as the symmetric key.  'keylen' must be 16, 24, or 32 bytes. */
  static gcm_decryptor *create(const uint8_t *key, size_t keylen);

  /** Return a new AES/GCM decryption state, generating a key of
      length 'keylen' from the key generator 'gen'.  'keylen' must be
      16, 24, or 32 bytes. */
  static gcm_decryptor *create(key_generator *gen, size_t keylen);

  /** Return a new AES/GCM decryption state that doesn't actually
      decrypt anything -- it just copies its input to its output.
      For testing purposes only.  */
  static gcm_decryptor *create_noop();

  /** Decrypt 'inlen' bytes of data in the buffer 'in'; the last 16
      bytes of this buffer are assumed to be the authentication tag.
      Write the result to the buffer 'out', whose length must be at
      least 'inlen'-16 bytes.  Use 'nonce' (of length 'nlen') as the
      encryption nonce; as above, 'nlen' must be at least 12 bytes.
      Returns 0 if successful, -1 if the authentication check fails. */
  virtual int decrypt(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint8_t *nonce, size_t nlen) = 0;

  virtual ~gcm_decryptor();
protected:
  gcm_decryptor() {}
private:
  gcm_decryptor(const gcm_decryptor&) DELETE_METHOD;
  gcm_decryptor& operator=(const gcm_decryptor&) DELETE_METHOD;
};

/** Encapsulation of an elliptic curve Diffie-Hellman message
    (we use NIST P-224).  */
struct ecdh_message
{
  /** Generate a new Diffie-Hellman message from randomness. */
  static ecdh_message *generate();

  /** Generate a new Diffie-Hellman message from a specified secret
      value (in the form of a big-endian byte string, EC_P224_LEN
      bytes long).  This is provided for testing purposes only; it
      should not be used in normal operation. */
  static ecdh_message *load_secret(const uint8_t *secret);

  /** Encode a Diffie-Hellman message to the wire format.  This
      produces only the x-coordinate of the chosen curve point.
      The argument must point to EC_P224_LEN bytes of buffer space. */
  virtual void encode(uint8_t *xcoord_out) const = 0;

  /** Combine our message with the wire-format message sent by our
      peer, and produce the raw ECDH shared secret.  |xcoord_other|
      must point to EC_P224_LEN bytes of data, and |secret_out| must
      point to the same quantity of buffer space.  Normally you should
      use key_generator::from_ecdh instead of calling this
      directly.  */
  virtual int combine(const uint8_t *xcoord_other, uint8_t *secret_out)
    const = 0;

  virtual ~ecdh_message();
protected:
  ecdh_message() {}
private:
  ecdh_message(const ecdh_message&) DELETE_METHOD;
  ecdh_message& operator=(const ecdh_message&) DELETE_METHOD;
};

/** Moeller key encapsulation generator: takes a public key and a source
    of weak entropy, produces temporary key material and key encapsulation
    messages.  */
struct mke_generator
{
  /** Return a new encapsulation generator based on the public key
      'key', which should be a C string of the form produced by
      'mke_decoder::pubkey()', and a key_generator.  The object
      retains references to both arguments, so make sure their
      lifetimes exceed that of this object.  You are encouraged
      to use key_generator::from_rng() for this.  */
  static mke_generator *create(const char *pubkey, key_generator *gen);

  /** Retrieve the public key.  This will be the same pointer as was
      passed to create().  */
  virtual const char *pubkey() const;

  /** Retrieve the length of the public key (you could call strlen(),
      but this may be more efficient).  */
  virtual size_t pklen() const;

  /** Generate temporary key material and an encapsulated key message.
      This does NOT carry out key derivation; you probably want to use
      key_generator::from_mke() instead.  The 'message' argument must
      point to at least MKE_MSG_LEN bytes of storage, and the 'secret'
      argument must point to at least twice that much storage.  */
  virtual int generate(uint8_t *secret, uint8_t *message) const;

  /** Extract the padding from a previously-generated encapsulated key
      message.  Cannot fail.  Do not attempt to interpret the byte
      returned; just pack it somewhere in the data encrypted with the
      derived key material, so that the receiver can verify it.  */
  virtual uint8_t extract_padding(uint8_t *message) const;

  virtual ~mke_generator();
protected:
  mke_generator() {}
private:
  mke_generator(const mke_generator&) DELETE_METHOD;
  mke_generator& operator=(const mke_generator&) DELETE_METHOD;
};

/** Moeller key encapsulation decoder: creates a keypair when
    instantiated, can be asked to emit the public key, can decode the
    counterpart's key encapsulation messages into temporary key material. */
struct mke_decoder
{
  /** Return a new encapsulation decoder.  Generates a new keypair
      from a source of strong entropy.  */
  static mke_decoder *create();

  /** Emit the public key.  The return value is a C-string.
      The storage for this string belongs to the mke_decoder object.
      Its contents are unspecified, but it uses only the characters
      ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=,
   */
  virtual const char *pubkey() const;

  /** Retrieve the length of the public key (you could call strlen(),
      but this may be more efficient).  */
  virtual size_t pklen() const;

  /** Decode an encapsulated key message.  This does NOT carry out key
      derivation; you probably want to use key_generator::from_mke()
      instead.  The 'message' argument must point to at least
      MKE_MSG_LEN bytes of data, and the 'secret' argument must point
      to at least twice that much storage.  */
  virtual int decode(uint8_t *secret, uint8_t *message) const;

  /** Extract the padding from an encapsulated key message.
      Cannot fail.  Do not attempt to interpret the byte returned;
      just verify it by comparing it with a byte somewhere in the
      data encrypted with the derived key material. */
  virtual uint8_t extract_padding(uint8_t *message) const;

  virtual ~mke_decoder();
protected:
  mke_decoder() {}
private:
  mke_decoder(const mke_decoder&) DELETE_METHOD;
  mke_decoder& operator=(const mke_decoder&) DELETE_METHOD;
};


/** Generate keying material from an initial key of some kind, a salt
    value, and a context value, all of which are formally bitstrings.
    See http://tools.ietf.org/html/rfc5869 for the requirements on the
    salt and the context.  'from_random_secret' uses HKDF as described
    in that document, and therefore requires the initial key to be a
    high-entropy random value; 'from_password' stretches a low-entropy
    passphrase with PBKDF2 first.  Either way, we use HKDF-Expand as
    the actual pseudo-random function.  */

struct key_generator
{
  /** Construct a key generator from a genuinely random secret, plus a
      salt value (should be as random as possible, does not have to be
      secret) and a context value (whatever you've got that uniquely
      identifies the application context; doesn't have to be random
      _or_ secret).  */
  static key_generator *from_random_secret(const uint8_t *key,  size_t klen,
                                           const uint8_t *salt, size_t slen,
                                           const uint8_t *ctxt, size_t clen);

  /** Construct a key generator from a passphrase.  The salt and context
      arguments are the same as for from_random_secret. */
  static key_generator *from_passphrase(const uint8_t *phra, size_t plen,
                                        const uint8_t *salt, size_t slen,
                                        const uint8_t *ctxt, size_t clen);

  /** Construct a key generator from two (elliptic curve) Diffie-Hellman
      messages. The salt and context arguments are the same as for
      from_random_secret. */
  static key_generator *from_ecdh(const ecdh_message *mine,
                                  const uint8_t *theirs,
                                  const uint8_t *salt, size_t slen,
                                  const uint8_t *ctxt, size_t clen);

  /** Construct a key generator from a Moeller key generator, and as a
      side effect, emit the key encapsulation message.  Will use the
      public key for the salt.  The 'message_out' argument must point
      to at least MKE_MSG_LEN bytes of storage.  */
  static key_generator *from_mke(const mke_generator *gen,
                                 uint8_t *message_out,
                                 const uint8_t *ctxt, size_t clen);

  /** Construct a key generator from a Moeller key decoder and a
      received key encapsulation message.  Will use the public key for
      the salt.  The 'message' argument must point to at least
      MKE_MSG_LEN bytes of data.  */
  static key_generator *from_mke(const mke_decoder *gen,
                                 uint8_t *message,
                                 const uint8_t *ctxt, size_t clen);

  /** Construct a key generator from the global random number
      generator.  This should be used in contexts where a great deal
      of key material may be required but its strength is not terribly
      important; it reduces the demand on the entropy source.  Key
      generators created by this factory will automatically reseed
      themselves when they hit the HKDF upper limit. */
  static key_generator *from_rng(const uint8_t *salt, size_t slen,
                                 const uint8_t *ctxt, size_t clen);

  /** Write LEN bytes of key material to BUF.  May be called
      repeatedly.  Note that HKDF has a hard upper limit on the total
      amount of key material it can generate.  The return value is
      therefore the amount of data actually written to BUF, and it
      will be no greater than LEN, but may be as short as zero. */
  virtual size_t generate(uint8_t *buf, size_t len) = 0;

  virtual ~key_generator();
  key_generator() {}
private:
  key_generator(const key_generator&) DELETE_METHOD;
  key_generator& operator=(const key_generator&) DELETE_METHOD;
};

viod sha256(unsigned char *buffer, size_t n, unsigned char *md);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);
#endif
