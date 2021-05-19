import forge from 'node-forge';
import { AuthenticatorTokenDTO } from './api';

// Got following functions from service workers

function isBase32(value: string) {
  return value.replace(/-|\s/g, '').match(/^[a-zA-Z2-7]+=*$/) !== null;
}

interface GeneratePBKDF2KeyOptions {
  iterations: number;
  keySize: number;
  decodeSalt: boolean;
  withoutEncoding: boolean;
}

function generatePBKDF2Key(password: string, salt: string, options: GeneratePBKDF2KeyOptions) {
  // eslint-disable-next-line no-param-reassign
  if (options.decodeSalt) salt = forge.util.hexToBytes(salt);

  if (options.withoutEncoding) {
    return forge.pkcs5.pbkdf2(password, salt, options.iterations, options.keySize);
  }

  return forge.pkcs5.pbkdf2(
    unescape(encodeURIComponent(password)),
    salt,
    options.iterations,
    options.keySize,
  );
}

function decryptAESWithKey(key: string, value: string) {
  const ivBuffer = forge.util.createBuffer(
    forge.util.decodeUtf8('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
  );
  const keyBuffer = forge.util.createBuffer(key);
  const valueBuffer = forge.util.createBuffer(forge.util.decode64(value));

  // forge.aes is deprecated, changed to forge.cipher.createDecipher
  // const decryptionCypher = forge.aes.createDecryptionCipher(keyBuffer, "CBC");
  // decryptionCypher.start(ivBuffer);
  // decryptionCypher.update(valueBuffer);
  // return decryptionCypher.finish() ? decryptionCypher.output.data : null;

  const decipher = forge.cipher.createDecipher('AES-CBC', keyBuffer);
  decipher.start({ iv: ivBuffer });
  decipher.update(valueBuffer);
  return decipher.finish() ? decipher.output.data : null;
}

function decryptAES(
  salt: string,
  password: string,
  value: string,
  withoutEncoding: boolean = false,
) {
  const pbkdf2Key = generatePBKDF2Key(password, salt, {
    iterations: 1000,
    keySize: 32, // Originally it was denoted in bits, changed to bytes
    decodeSalt: false,
    withoutEncoding,
  });

  return decryptAESWithKey(pbkdf2Key, value);
}

interface DecryptedToken extends AuthenticatorTokenDTO {
  decrypted_seed: string;
}

export default function decryptTokens(tokens: AuthenticatorTokenDTO[], password: string) {
  return tokens.reduce<DecryptedToken[]>((decryptedTokens, token) => {
    let decrypted = decryptAES(token.salt, password, token.encrypted_seed, false);
    if (decrypted === null || !isBase32(decrypted)) {
      decrypted = decryptAES(token.salt, password, token.encrypted_seed, true);
      if (decrypted === null || !isBase32(decrypted)) {
        return decryptedTokens;
      }
    }

    decryptedTokens.push({ ...token, decrypted_seed: decrypted });
    return decryptedTokens;
  }, []);
}
