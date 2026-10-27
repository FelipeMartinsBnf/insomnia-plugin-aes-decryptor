const CryptoJS = require('crypto-js');
const {
  EXPECTED_KEY_BYTES
} = require('./constants');
const {
  isValidBase64,
  getBase64ByteLength
} = require('./utils');

/**
 * Resultado do processo de criptografia.
 * @typedef {Object} EncryptResult
 * @property {boolean} success - Se a criptografia foi bem-sucedida.
 * @property {string|null} encryptedBase64 - Texto criptografado em Base64.
 * @property {string|null} error - Mensagem de diagnóstico caso haja falha.
 * @property {string|null} code - Código identificador do motivo do erro/ignorado.
 */

/**
 * Verifica se um texto já se encontra criptografado em Base64 (para evitar dupla cifra).
 * @param {string} text
 * @returns {boolean}
 */
function isAlreadyEncrypted(text) {
  if (!text || typeof text !== 'string') {
    return false;
  }
  const trimmed = text.trim();
  // Se contiver estruturas JSON ou formato legível de objeto/array, não está criptografado
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return false;
  }
  // Se for Base64 válido e seu tamanho decodificado for múltiplo de 16 bytes do AES
  if (isValidBase64(trimmed)) {
    const byteLength = getBase64ByteLength(trimmed);
    if (byteLength > 0 && byteLength % 16 === 0) {
      return true;
    }
  }
  return false;
}

/**
 * Executa todas as etapas de validação e criptografia AES-128-ECB PKCS7.
 *
 * @param {string} plaintext - Texto original em claro (ex: JSON).
 * @param {string} keyString - Chave AES configurada em UTF-8 (16 bytes).
 * @returns {EncryptResult}
 */
function encryptAesPayload(plaintext, keyString) {
  // 1. Validação do texto
  if (plaintext === undefined || plaintext === null) {
    return {
      success: false,
      error: 'Corpo da requisição vazio ou indefinido.',
      code: 'EMPTY_BODY'
    };
  }

  const rawText = typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);
  if (rawText.trim().length === 0) {
    return {
      success: false,
      error: 'Corpo da requisição vazio.',
      code: 'EMPTY_BODY'
    };
  }

  // 2. Validação da chave
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

  // 3. Criptografia AES-128-ECB PKCS7
  try {
    const key = CryptoJS.enc.Utf8.parse(keyString);
    const encrypted = CryptoJS.AES.encrypt(
      CryptoJS.enc.Utf8.parse(rawText),
      key,
      {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
      }
    );

    const base64 = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
    return {
      success: true,
      encryptedBase64: base64,
      error: null,
      code: 'SUCCESS'
    };
  } catch (err) {
    return {
      success: false,
      error: `Falha na criptografia AES: ${err.message}`,
      code: 'ENCRYPT_FAILED'
    };
  }
}

module.exports = {
  isAlreadyEncrypted,
  encryptAesPayload
};
