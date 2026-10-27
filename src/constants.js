/**
 * Constantes utilizadas pelo plugin AES Crypto & Decryptor
 */

module.exports = {
  // Nomes de variáveis de ambiente pesquisadas para a chave AES
  KEY_ENV_NAMES: ['aes-cripto-key', 'aes-crypto-key', 'aes-key', 'AES_KEY'],

  // Nomes de variáveis de ambiente pesquisadas para a lista de hosts protegidos
  HOSTS_ENV_NAMES: ['aes-cripto-hosts', 'aes-crypto-hosts'],

  // Nomes de variáveis de ambiente pesquisadas para filtrar caminhos específicos (opcional)
  PATHS_ENV_NAMES: ['aes-cripto-paths', 'aes-crypto-paths'],

  // Chaves de armazenamento persistente do plugin
  STORE_KEY_AES: 'aes-cripto-key',
  STORE_HOSTS_KEY: 'aes-cripto-hosts',

  // Tamanho do bloco AES em bytes (AES-128 = 16 bytes)
  AES_BLOCK_SIZE_BYTES: 16,

  // Tamanho esperado da chave AES-128 em bytes UTF-8
  EXPECTED_KEY_BYTES: 16
};
