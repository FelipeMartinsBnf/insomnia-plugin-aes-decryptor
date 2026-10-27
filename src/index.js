const {
  resolveUrl,
  getHostname,
  getPathname,
  resolveProtectedHosts,
  isProtectedHost,
  resolvePathFilters,
  isPathAllowed,
  resolveEncryptionKey
} = require('./utils');
const { decryptAesPayload } = require('./decryptor');
const { encryptAesPayload, isAlreadyEncrypted } = require('./encryptor');

/**
 * Hook de requisição do Insomnia.
 * Executado automaticamente antes de cada requisição HTTP ser enviada.
 * Criptografa o body JSON em AES-128-ECB Base64 para os hosts protegidos configurados em aes-cripto-hosts.
 *
 * @param {object} context - Objeto de contexto do plugin fornecido pelo Insomnia.
 */
async function requestHook(context) {
  try {
    if (!context || !context.request) {
      return;
    }

    // 1. Identificar a URL da requisição (resolvendo tags de template como {{base_url}} se presentes)
    const rawUrl = context.request.getUrl();
    if (!rawUrl || typeof rawUrl !== 'string') {
      return;
    }

    const resolvedUrl = resolveUrl(rawUrl, context);
    const hostname = getHostname(resolvedUrl) || getHostname(rawUrl);
    if (!hostname) {
      return;
    }

    // Obter lista de hosts protegidos configurados em aes-cripto-hosts
    const protectedHosts = await resolveProtectedHosts(context);

    // Verificar se pertence à lista de hosts protegidos
    if (!isProtectedHost(hostname, protectedHosts)) {
      return;
    }

    // Filtragem opcional de caminhos específicos
    const pathFilters = resolvePathFilters(context);
    const pathname = getPathname(resolvedUrl);
    if (!isPathAllowed(pathname, pathFilters)) {
      return;
    }

    // 3. Obter o corpo original da requisição
    const bodyObj = context.request.getBody();
    let plaintext = '';
    if (bodyObj) {
      if (typeof bodyObj.text === 'string') {
        plaintext = bodyObj.text;
      } else if (typeof bodyObj.raw === 'string') {
        plaintext = bodyObj.raw;
      } else if (typeof bodyObj === 'string') {
        plaintext = bodyObj;
      }
    }
    if (!plaintext && typeof context.request.getBodyText === 'function') {
      try {
        plaintext = context.request.getBodyText() || '';
      } catch {}
    }

    if (!plaintext || plaintext.trim().length === 0) {
      // Requisição sem corpo (ex: GET simples) - nada a fazer
      return;
    }

    // Se o corpo já estiver criptografado (evita dupla cifra caso o usuário já tenha colado Base64)
    if (isAlreadyEncrypted(plaintext)) {
      console.log(`[AES Encryptor] Corpo de [${resolvedUrl}] já se encontra em Base64 criptografado. Criptografia ignorada.`);
      return;
    }

    // 4. Obter a chave de criptografia a partir do ambiente ativo
    const keyString = await resolveEncryptionKey(context);
    if (!keyString) {
      console.warn(`[AES Encryptor] Requisição para [${resolvedUrl}] não foi criptografada: chave "aes-cripto-key" ausente no ambiente ativo.`);
      return;
    }

    // 5. Criptografar o corpo em AES-128-ECB PKCS7 Base64
    const result = encryptAesPayload(plaintext, keyString);
    if (!result.success) {
      console.warn(`[AES Encryptor] Falha ao criptografar requisição para [${resolvedUrl}]: ${result.error}`);
      return;
    }

    const base64 = result.encryptedBase64;

    // 6. Atualizar o corpo da requisição para a versão criptografada
    const updatedBody = {
      mimeType: 'application/json',
      text: base64
    };

    if (typeof context.request.setBody === 'function') {
      context.request.setBody(updatedBody);
    } else if (typeof context.request.setBodyText === 'function') {
      context.request.setBodyText(base64);
    }

    // Atualizar cabeçalhos para Content-Type: application/json e remover Content-Length
    if (typeof context.request.removeHeader === 'function') {
      context.request.removeHeader('Content-Length');
    }
    if (typeof context.request.setHeader === 'function') {
      context.request.setHeader('Content-Type', 'application/json');
    } else if (typeof context.request.addHeader === 'function') {
      context.request.addHeader('Content-Type', 'application/json');
    }

    // 7. Registrar logs no console do Insomnia
    console.log(`[AES Encryptor] Corpo original antes da criptografia de [${resolvedUrl}]:\n${plaintext}`);
    console.log(`[AES Encryptor] Body final criptografado (Base64) para [${resolvedUrl}]:\n${base64}`);

    try {
      const fs = require('fs');
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] requestHook: body encrypted successfully (${Buffer.byteLength(base64, 'utf8')} bytes)\n`);
    } catch {}
  } catch (err) {
    console.error(`[AES Encryptor] Erro inesperado ao processar requisição: ${err.message}`);
  }
}

/**
 * Hook de resposta do Insomnia.
 * Executado automaticamente após cada resposta HTTP recebida.
 *
 * @param {object} context - Objeto de contexto do plugin fornecido pelo Insomnia.
 */
async function responseHook(context) {
  try {
    const fs = require('fs');
    fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] responseHook called!\n`);

    if (!context || !context.response || !context.request) {
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] context, response or request missing\n`);
      return;
    }

    // 1. Identificar a URL da requisição (resolvendo tags de template como {{base_url}} se presentes)
    const rawUrl = context.request.getUrl();
    fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] rawUrl: ${rawUrl}\n`);
    if (!rawUrl || typeof rawUrl !== 'string') {
      return;
    }

    const resolvedUrl = resolveUrl(rawUrl, context);
    const hostname = getHostname(resolvedUrl) || getHostname(rawUrl);
    fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] resolvedUrl: ${resolvedUrl}, hostname: ${hostname}\n`);
    if (!hostname) {
      return;
    }

    // Obter lista de hosts protegidos
    const protectedHosts = await resolveProtectedHosts(context);
    fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] protectedHosts: ${JSON.stringify(protectedHosts)}\n`);

    // Verificar se pertence à lista de hosts protegidos
    if (!isProtectedHost(hostname, protectedHosts)) {
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] ignored: not protected host\n`);
      return;
    }

    // Filtragem opcional de caminhos específicos
    const pathFilters = resolvePathFilters(context);
    const pathname = getPathname(resolvedUrl);
    if (!isPathAllowed(pathname, pathFilters)) {
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] ignored: path not allowed\n`);
      return;
    }

    // 4. Obter o corpo original da resposta
    let rawBuffer;
    try {
      rawBuffer = await context.response.getBody();
      const bufferType = rawBuffer ? Object.prototype.toString.call(rawBuffer) : 'null';
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] rawBuffer length: ${rawBuffer?.length}, type: ${bufferType}\n`);
    } catch (bodyErr) {
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] getBody error: ${bodyErr.message}\n`);
      console.warn(`[AES Decryptor] Falha ao ler corpo da resposta: ${bodyErr.message}`);
      return;
    }

    if (!rawBuffer || rawBuffer.length === 0) {
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] empty body\n`);
      console.info(`[AES Decryptor] Resposta ignorada para ${resolvedUrl}: corpo vazio.`);
      return;
    }

    // Converter para string UTF-8 suportando Node.js Buffer, Electron/Chromium Uint8Array e ArrayBuffer
    let rawText = '';
    if (typeof rawBuffer === 'string') {
      rawText = rawBuffer;
    } else if (Buffer.isBuffer(rawBuffer)) {
      rawText = rawBuffer.toString('utf8');
    } else if (rawBuffer instanceof Uint8Array || rawBuffer instanceof ArrayBuffer) {
      rawText = new TextDecoder('utf-8').decode(rawBuffer);
    } else {
      rawText = Buffer.from(rawBuffer).toString('utf8');
    }

    rawText = rawText.trim();
    if (rawText.length === 0) {
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] empty text body\n`);
      console.info(`[AES Decryptor] Resposta ignorada para ${resolvedUrl}: corpo vazio.`);
      return;
    }

    fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] rawText length: ${rawText.length}, starts with: ${rawText.slice(0, 30)}\n`);

    // 5. Registrar o corpo original, ainda criptografado, no console antes de qualquer modificação
    console.log(`[AES Decryptor] Corpo original criptografado (Base64) de [${resolvedUrl}]:\n${rawText}`);

    // Obter a chave de criptografia a partir do ambiente ativo, store do plugin ou Base Environment
    const keyString = await resolveEncryptionKey(context);
    fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] key resolved: ${keyString ? 'YES (length ' + keyString.length + ')' : 'NO'}\n`);

    // Executar validações completas e descriptografia
    const result = decryptAesPayload(rawText, keyString);
    fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] decrypt result success: ${result.success}, error: ${result.error}\n`);

    if (result.success) {
      // 13. Substituir o corpo da resposta por JSON formatado (indentação de 2 espaços)
      await context.response.setBody(Buffer.from(result.formattedJson, 'utf8'));
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] setBody called successfully!\n`);
      console.log(`[AES Decryptor] Sucesso: Resposta de [${resolvedUrl}] descriptografada e substituída por JSON formatado.`);
    } else {
      // 14. Se alguma validação falhar, manter o corpo original e emitir diagnóstico apropriado
      console.warn(`[AES Decryptor] Diagnóstico para [${resolvedUrl}]: ${result.error}`);
    }
  } catch (err) {
    try {
      const fs = require('fs');
      fs.appendFileSync('/tmp/plugin_trace.log', `[${new Date().toISOString()}] unexpected error: ${err.message}\n${err.stack}\n`);
    } catch {}
    // Tratar erros com try/catch sem interromper a exibição da resposta original
    console.error(`[AES Decryptor] Erro inesperado no processamento da resposta: ${err.message}`);
  }
}

/**
 * Ação de workspace para inspecionar configurações e testar status do plugin no Insomnia.
 */
const workspaceActions = [
  {
    label: 'AES Decryptor: Status e Diagnóstico',
    icon: 'fa-shield-halved',
    action: async (context, models) => {
      try {
        const protectedHosts = await resolveProtectedHosts(context);
        const keyString = await resolveEncryptionKey(context);

        let keyStatus;
        if (!keyString) {
          keyStatus = 'NÃO CONFIGURADA (variável "aes-cripto-key" ausente no ambiente ativo)';
        } else {
          const byteLen = Buffer.byteLength(keyString, 'utf8');
          if (byteLen === 16) {
            keyStatus = 'CONFIGURADA CORRETAMENTE (16 bytes UTF-8)';
          } else {
            keyStatus = `INVÁLIDA (${byteLen} bytes - o algoritmo AES-128 exige 16 bytes)`;
          }
        }

        const hostsListStr = protectedHosts.length > 0
          ? protectedHosts.join(', ')
          : 'NENHUM (defina "aes-cripto-hosts" no ambiente com os domínios desejados)';

        const infoMessage = [
          'Plugin: AES Crypto & Decryptor (AES-128-ECB)',
          '--------------------------------------------',
          `Status da Chave (aes-cripto-key): ${keyStatus}`,
          `Hosts Protegidos: ${hostsListStr}`,
          '',
          'Instruções:',
          '1. Criptografia Automática de Envio (Request Hook): O corpo JSON é criptografado em Base64 automaticamente antes do envio.',
          '2. Descriptografia Automática de Resposta (Response Hook): A resposta Base64 é descriptografada e exibida como JSON formatado.',
          '3. Você pode escrever JSON normalmente no corpo da requisição (não precisa de pre-request script).',
          '4. Os corpos originais e criptografados são registrados no Console do Insomnia (Ctrl+Shift+I -> Console).'
        ].join('\n');

        if (context.app && typeof context.app.alert === 'function') {
          await context.app.alert('AES Decryptor - Status', infoMessage);
        } else {
          console.log('[AES Decryptor Status]\n' + infoMessage);
        }
      } catch (e) {
        console.error('[AES Decryptor] Erro ao obter status:', e.message);
      }
    }
  }
];

module.exports = {
  requestHooks: [requestHook],
  responseHooks: [responseHook],
  workspaceActions
};
