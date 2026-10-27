const CryptoJS = require('crypto-js');
const {
  AES_BLOCK_SIZE_BYTES,
  EXPECTED_KEY_BYTES
} = require('./constants');
const {
  sanitizeBase64,
  isValidBase64,
  getBase64ByteLength
} = require('./utils');

/**
 * Resultado do processo de descriptografia.
 * @typedef {Object} DecryptResult
 * @property {boolean} success - Se a descriptografia e validação do JSON foram bem-sucedidas.
 * @property {string|null} formattedJson - JSON formatado com 2 espaços de indentação, se sucesso.
 * @property {object|null} parsedJson - Objeto JSON decodificado.
 * @property {string|null} error - Mensagem de diagnóstico caso haja falha.
 * @property {string|null} code - Código identificador do motivo do erro/ignorado.
 */

/**
 * Executa todas as etapas de validação e descriptografia AES-128-ECB PKCS7.
 *
 * @param {string|Buffer|Uint8Array} encryptedBase64 - Corpo da resposta contendo a string Base64.
 * @param {string} keyString - Chave AES configurada em UTF-8.
 * @returns {DecryptResult}
 */
function decryptAesPayload(encryptedBase64, keyString) {
  // 1. Validação da presença e formato básico do corpo
  if (!encryptedBase64) {
    return {
      success: false,
      error: 'Corpo da resposta vazio ou inválido.',
      code: 'EMPTY_BODY'
    };
  }

  let rawStr = '';
  if (typeof encryptedBase64 === 'string') {
    rawStr = encryptedBase64;
  } else if (Buffer.isBuffer(encryptedBase64)) {
    rawStr = encryptedBase64.toString('utf8');
  } else if (encryptedBase64 instanceof Uint8Array || encryptedBase64 instanceof ArrayBuffer) {
    rawStr = new TextDecoder('utf-8').decode(encryptedBase64);
  } else {
    return {
      success: false,
      error: 'Corpo da resposta vazio ou inválido.',
      code: 'EMPTY_BODY'
    };
  }

  const trimmedCiphertext = sanitizeBase64(rawStr);
  if (trimmedCiphertext.length === 0) {
    return {
      success: false,
      error: 'Corpo da resposta vazio.',
      code: 'EMPTY_BODY'
    };
  }

  // 2. Validação se é um candidato a Base64
  if (!isValidBase64(trimmedCiphertext)) {
    return {
      success: false,
      error: 'O conteúdo da resposta não é uma string Base64 válida.',
      code: 'INVALID_BASE64'
    };
  }

  // 3. Validação do tamanho em bytes do Base64 (deve ser múltiplo de 16 bytes do bloco AES)
  const byteLength = getBase64ByteLength(trimmedCiphertext);
  if (byteLength === 0 || byteLength % AES_BLOCK_SIZE_BYTES !== 0) {
    return {
      success: false,
      error: `Tamanho dos dados decodificados (${byteLength} bytes) não corresponde a blocos completos de AES (${AES_BLOCK_SIZE_BYTES} bytes).`,
      code: 'INVALID_BLOCK_SIZE'
    };
  }

  // 4. Validação da chave de criptografia
  if (!keyString || typeof keyString !== 'string') {
    return {
      success: false,
      error: 'Chave de criptografia "aes-cripto-key" ausente ou não configurada no ambiente ativo.',
      code: 'MISSING_KEY'
    };
  }

  const keyBytes = CryptoJS.enc.Utf8.parse(keyString).sigBytes;
  if (keyBytes !== EXPECTED_KEY_BYTES) {
    return {
      success: false,
      error: `Chave de criptografia possui tamanho inválido (${keyBytes} bytes UTF-8). O algoritmo AES-128 exige exatamente ${EXPECTED_KEY_BYTES} bytes.`,
      code: 'INVALID_KEY_LENGTH'
    };
  }

  // 5. Descriptografia AES-128-ECB PKCS7
  let plaintext;
  try {
    const key = CryptoJS.enc.Utf8.parse(keyString);
    const ciphertext = CryptoJS.enc.Base64.parse(trimmedCiphertext);

    const decrypted = CryptoJS.AES.decrypt(
      CryptoJS.lib.CipherParams.create({ ciphertext }),
      key,
      {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
      }
    );

    plaintext = CryptoJS.enc.Utf8.stringify(decrypted);
  } catch (decryptErr) {
    return {
      success: false,
      error: `Falha na descriptografia AES: ${decryptErr.message}`,
      code: 'DECRYPT_FAILED'
    };
  }

  // 6. Validação do resultado descriptografado
  if (!plaintext || plaintext.length === 0) {
    return {
      success: false,
      error: 'Falha na descriptografia: resultado vazio ou padding PKCS7 inválido (verifique se a chave corresponde aos dados).',
      code: 'DECRYPT_FAILED'
    };
  }

  // 7. Validação do JSON
  let parsedJson;
  try {
    parsedJson = JSON.parse(plaintext);
  } catch (jsonErr) {
    return {
      success: false,
      error: `Texto descriptografado não é um JSON válido: ${jsonErr.message}`,
      code: 'INVALID_JSON'
    };
  }

  // 8. Formatação do JSON com 2 espaços de indentação
  const formattedJson = JSON.stringify(parsedJson, null, 2);

  return {
    success: true,
    formattedJson,
    parsedJson,
    error: null,
    code: 'SUCCESS'
  };
}

module.exports = {
  decryptAesPayload
};
