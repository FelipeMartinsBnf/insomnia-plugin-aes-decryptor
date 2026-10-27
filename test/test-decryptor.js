const assert = require('assert');
const fs = require('fs');
const path = require('path');
const CryptoJS = require('crypto-js');

// Carrega o plugin compilado (o mesmo que o Insomnia carrega)
const plugin = require('../index.js');
const { responseHooks, requestHooks } = plugin;
const hook = responseHooks[0];
const reqHook = requestHooks ? requestHooks[0] : null;

const TEST_AES_KEY = '1234567890abcdef'; // Chave fictícia de teste (16 bytes UTF-8)
const PROTECTED_HOST = 'api.empresa.com.br';
const PROTECTED_URL = `https://${PROTECTED_HOST}/auth/login`;
const LOCAL_URL = 'http://localhost:8080/auth/login';
const OTHER_HOST_URL = 'https://api.github.com/users/octocat';

/**
 * Cria um contexto simulado do Insomnia para o responseHook e requestHook
 */
function createMockContext({
  url = PROTECTED_URL,
  body = '',
  requestBody = null,
  env = {
    'aes-cripto-key': TEST_AES_KEY,
    'aes-cripto-hosts': `${PROTECTED_HOST}, hml.empresa.com.br`
  },
  store = {}
}) {
  let currentBody = Buffer.from(body);
  let currentReqBody = requestBody !== null
    ? (typeof requestBody === 'object' ? requestBody : { mimeType: 'application/json', text: String(requestBody) })
    : { mimeType: 'application/json', text: '' };

  let requestHeaders = [
    { name: 'Content-Type', value: 'application/json' },
    { name: 'Content-Length', value: '123' }
  ];

  const logs = [];
  const warns = [];
  const errors = [];

  // Mock console to capture outputs
  const mockConsole = {
    log: (...args) => logs.push(args.join(' ')),
    warn: (...args) => warns.push(args.join(' ')),
    info: (...args) => logs.push(args.join(' ')),
    error: (...args) => errors.push(args.join(' '))
  };

  const context = {
    _isMock: true,
    request: {
      getUrl: () => url,
      getEnvironmentVariable: (key) => env[key],
      getEnvironment: () => env,
      getBody: () => currentReqBody,
      setBody: (b) => { currentReqBody = b; },
      getBodyText: () => currentReqBody?.text || '',
      setBodyText: (t) => {
        if (!currentReqBody) currentReqBody = { mimeType: 'application/json' };
        currentReqBody.text = t;
      },
      getHeader: (n) => requestHeaders.find(h => h.name.toLowerCase() === n.toLowerCase())?.value || null,
      getHeaders: () => requestHeaders,
      setHeader: (n, v) => {
        const existing = requestHeaders.find(h => h.name.toLowerCase() === n.toLowerCase());
        if (existing) existing.value = v;
        else requestHeaders.push({ name: n, value: v });
      },
      addHeader: (n, v) => { requestHeaders.push({ name: n, value: v }); },
      removeHeader: (n) => {
        requestHeaders = requestHeaders.filter(h => h.name.toLowerCase() !== n.toLowerCase());
      }
    },
    response: {
      getBody: async () => currentBody,
      setBody: async (newBody) => {
        currentBody = Buffer.isBuffer(newBody) ? newBody : Buffer.from(newBody, 'utf8');
      },
      getHeader: () => 'application/json',
      getHeaders: () => [{ name: 'content-type', value: 'application/json' }],
      hasHeader: (h) => h.toLowerCase() === 'content-type'
    },
    store: {
      getItem: async (key) => store[key] || null,
      setItem: async (key, val) => { store[key] = val; }
    }
  };

  return {
    context,
    mockConsole,
    logs,
    warns,
    errors,
    getBodyString: () => currentBody.toString('utf8'),
    getBodyBuffer: () => currentBody,
    getRequestBodyText: () => currentReqBody?.text || '',
    getRequestHeaders: () => requestHeaders
  };
}

/**
 * Utilitário para cifrar um texto no mesmo formato da API (AES-128-ECB PKCS7 Base64)
 */
function encryptPayload(plaintext, keyStr) {
  const key = CryptoJS.enc.Utf8.parse(keyStr);
  const encrypted = CryptoJS.AES.encrypt(
    CryptoJS.enc.Utf8.parse(plaintext),
    key,
    {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7
    }
  );
  return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
}

// Intercepta console global durante os testes para validações
const origConsole = { ...console };

async function runWithConsole(mock, fn) {
  console.log = mock.log;
  console.warn = mock.warn;
  console.info = mock.info;
  console.error = mock.error;
  try {
    await fn();
  } finally {
    console.log = origConsole.log;
    console.warn = origConsole.warn;
    console.info = origConsole.info;
    console.error = origConsole.error;
  }
}

async function runTests() {
  origConsole.log('====================================================');
  origConsole.log(' Executando bateria de testes do plugin AES Crypto');
  origConsole.log('====================================================\n');

  let passed = 0;
  let total = 0;

  async function test(name, fn) {
    total++;
    try {
      await fn();
      origConsole.log(`  ✓ Caso ${total}: ${name}`);
      passed++;
    } catch (e) {
      origConsole.error(`  ✗ Caso ${total} FALHOU: ${name}`);
      origConsole.error('    Detalhe:', e.message);
      origConsole.error(e.stack);
    }
  }

  // 1. Resposta criptografada válida: o corpo é descriptografado e aparece como JSON formatado
  await test('Resposta criptografada válida -> Descriptografa e formata como JSON', async () => {
    const rawJson = '{"access_token":"token_123","user":{"id":42,"nome":"Teste"}}';
    const encrypted = encryptPayload(rawJson, TEST_AES_KEY);
    const mock = createMockContext({ url: PROTECTED_URL, body: encrypted });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const result = mock.getBodyString();
    assert.notStrictEqual(result, encrypted);
    const parsed = JSON.parse(result);
    assert.strictEqual(parsed.access_token, 'token_123');
    assert.strictEqual(parsed.user.nome, 'Teste');
    assert(result.includes('  "access_token": "token_123"'), 'Deve conter indentação de 2 espaços');
  });

  // 1b. Teste com resposta de autenticação (JWT)
  await test('Resposta de autenticação com JWT -> Descriptografa com chave aes-cripto-key', async () => {
    const loginResponse = JSON.stringify({
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlVzdWFyaW8ifQ.signature',
      token_type: 'Bearer',
      expires_in: 3600
    });
    const encrypted = encryptPayload(loginResponse, TEST_AES_KEY);
    const mock = createMockContext({ url: PROTECTED_URL, body: encrypted });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const result = mock.getBodyString();
    const parsed = JSON.parse(result);
    assert(parsed.access_token && parsed.access_token.length > 50, 'Deve conter access_token JWT');
    assert(result.includes('  "token_type": "Bearer"'), 'Deve conter token_type formatado');
  });

  // 1c. Teste com URL contendo tags de template genéricas (ex: {{base_url}}/auth/login)
  await test('Resposta com URL contendo tag {{base_url}} -> Resolve URL e descriptografa normalmente', async () => {
    const rawJson = '{"resultado":"sucesso_template_tag"}';
    const encrypted = encryptPayload(rawJson, TEST_AES_KEY);
    const mock = createMockContext({
      url: '{{base_url}}/auth/login',
      body: encrypted,
      env: {
        'base_url': `https://${PROTECTED_HOST}`,
        'aes-cripto-hosts': PROTECTED_HOST,
        'aes-cripto-key': TEST_AES_KEY
      }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const result = mock.getBodyString();
    const parsed = JSON.parse(result);
    assert.strictEqual(parsed.resultado, 'sucesso_template_tag');
  });

  // 1d. Teste com URL contendo tag {{ _.base_url }}
  await test('Resposta com URL contendo tag {{ _.base_url }} -> Resolve URL e descriptografa normalmente', async () => {
    const rawJson = '{"resultado":"sucesso_underscore_tag"}';
    const encrypted = encryptPayload(rawJson, TEST_AES_KEY);
    const mock = createMockContext({
      url: '{{ _.base_url }}/auth/login',
      body: encrypted,
      env: {
        'base_url': `https://${PROTECTED_HOST}`,
        'aes-cripto-hosts': PROTECTED_HOST,
        'aes-cripto-key': TEST_AES_KEY
      }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const result = mock.getBodyString();
    const parsed = JSON.parse(result);
    assert.strictEqual(parsed.resultado, 'sucesso_underscore_tag');
  });

  // 2. Sem hosts configurados em aes-cripto-hosts: tudo passa inalterado (Nenhum host padrão)
  await test('Sem hosts configurados em aes-cripto-hosts -> NADA é descriptografado (sem hosts padrão)', async () => {
    const rawJson = '{"dados":"teste"}';
    const encrypted = encryptPayload(rawJson, TEST_AES_KEY);
    const mock = createMockContext({
      url: PROTECTED_URL,
      body: encrypted,
      env: { 'aes-cripto-key': TEST_AES_KEY } // Sem 'aes-cripto-hosts'
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    // Permanece como encrypted Base64 pois não há hosts protegidos configurados
    assert.strictEqual(mock.getBodyString(), encrypted);
  });

  // 3. Resposta local sem criptografia (quando localhost não está na lista): o corpo permanece inalterado
  await test('Resposta local (localhost) sem estar na lista -> Corpo permanece inalterado', async () => {
    const originalBody = '{"status":"ok","local":true}';
    const mock = createMockContext({ url: LOCAL_URL, body: originalBody });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), originalBody);
  });

  // 3b. Resposta para localhost quando localhost ESTÁ na lista aes-cripto-hosts: deve descriptografar
  await test('Resposta local (localhost) quando localhost está em aes-cripto-hosts -> Descriptografa com sucesso', async () => {
    const testObj = { localTest: 'sucesso_localhost' };
    const encrypted = encryptPayload(JSON.stringify(testObj), TEST_AES_KEY);
    const mock = createMockContext({
      url: 'http://localhost:8080/auth/login',
      body: encrypted,
      env: { 'aes-cripto-key': TEST_AES_KEY, 'aes-cripto-hosts': 'localhost, 127.0.0.1' }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const expectedFormatted = JSON.stringify(testObj, null, 2);
    assert.strictEqual(mock.getBodyString(), expectedFormatted);
  });

  // 4. Suporte a curingas/wildcards (*.dominio.com)
  await test('Suporte a curinga (*.empresa.com.br) -> Descriptografa subdomínios', async () => {
    const testObj = { wildcard: true };
    const encrypted = encryptPayload(JSON.stringify(testObj), TEST_AES_KEY);
    const mock = createMockContext({
      url: 'https://hml.api.empresa.com.br/teste',
      body: encrypted,
      env: { 'aes-cripto-key': TEST_AES_KEY, 'aes-cripto-hosts': '*.empresa.com.br' }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const expectedFormatted = JSON.stringify(testObj, null, 2);
    assert.strictEqual(mock.getBodyString(), expectedFormatted);
  });

  // 5. Resposta de outro host não listado: o corpo permanece inalterado
  await test('Resposta de outro host não protegido -> Corpo permanece inalterado', async () => {
    const originalBody = '{"login":"octocat","type":"User"}';
    const mock = createMockContext({ url: OTHER_HOST_URL, body: originalBody });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), originalBody);
  });

  // 6. Resposta com Base64 inválido: o corpo permanece inalterado
  await test('Resposta com Base64 inválido -> Corpo permanece inalterado e loga diagnóstico', async () => {
    const invalidBase64 = 'EstaRespostaNaoEBase64!!@@##$$';
    const mock = createMockContext({ url: PROTECTED_URL, body: invalidBase64 });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), invalidBase64);
    assert(mock.warns.some(w => w.includes('Base64 válida')), 'Deve conter aviso de Base64 inválido');
  });

  // 7. Resposta com bloco AES válido mas falha na descriptografia
  await test('Resposta com bloco AES válido mas falha na descriptografia (bytes corrompidos) -> Permanece inalterado', async () => {
    const badCiphertext = Buffer.alloc(32, 0x41).toString('base64');
    const mock = createMockContext({ url: PROTECTED_URL, body: badCiphertext });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), badCiphertext);
    assert(mock.warns.some(w => w.includes('Falha na descriptografia')), 'Deve registrar diagnóstico de falha de descriptografia');
  });

  // 8. Resposta descriptografada que não é JSON: o corpo permanece inalterado
  await test('Resposta descriptografada válida que NÃO é JSON -> Corpo permanece inalterado', async () => {
    const rawPlaintext = 'Texto simples não formatado como JSON';
    const encrypted = encryptPayload(rawPlaintext, TEST_AES_KEY);
    const mock = createMockContext({ url: PROTECTED_URL, body: encrypted });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), encrypted);
    assert(mock.warns.some(w => w.includes('não é um JSON válido')), 'Deve registrar diagnóstico de JSON inválido');
  });

  // 9. Resposta vazia: o plugin não causa falha
  await test('Resposta vazia -> Não causa falha e mantém vazio', async () => {
    const mock = createMockContext({ url: PROTECTED_URL, body: '' });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), '');
    assert.strictEqual(mock.errors.length, 0, 'Não deve emitir erros não tratados');
  });

  // 10. Console: contém o corpo original criptografado, sem expor a chave
  await test('Console contém o corpo original criptografado e NÃO expõe a chave', async () => {
    const rawJson = '{"teste":"console"}';
    const encrypted = encryptPayload(rawJson, TEST_AES_KEY);
    const mock = createMockContext({ url: PROTECTED_URL, body: encrypted });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const allOutput = [...mock.logs, ...mock.warns, ...mock.errors].join('\n');
    assert(allOutput.includes(encrypted), 'Console deve conter a string Base64 original');
    assert(!allOutput.includes(TEST_AES_KEY), 'A chave AES NUNCA deve ser exposta nos logs');
  });

  // 11. Chave ausente no ambiente
  await test('Chave ausente no ambiente -> Mantém corpo inalterado e emite aviso', async () => {
    const encrypted = encryptPayload('{"a":1}', TEST_AES_KEY);
    const mock = createMockContext({
      url: PROTECTED_URL,
      body: encrypted,
      env: { 'aes-cripto-hosts': PROTECTED_HOST } // host protegido mas sem chave
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), encrypted);
    assert(mock.warns.some(w => w.includes('ausente')), 'Deve registrar diagnóstico de chave ausente');
  });

  // 12. Chave com tamanho inválido
  await test('Chave com tamanho inválido (diferente de 16 bytes UTF-8) -> Mantém inalterado e emite aviso', async () => {
    const encrypted = encryptPayload('{"a":1}', TEST_AES_KEY);
    const mock = createMockContext({
      url: PROTECTED_URL,
      body: encrypted,
      env: { 'aes-cripto-hosts': PROTECTED_HOST, 'aes-cripto-key': 'chave10byt' }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    assert.strictEqual(mock.getBodyString(), encrypted);
    assert(mock.warns.some(w => w.includes('tamanho inválido')), 'Deve registrar diagnóstico de tamanho inválido');
  });

  // 13. Suporte a variável em inglês "aes-crypto-key" e "aes-crypto-hosts"
  await test('Suporte a chave/hosts em inglês: aes-crypto-key e aes-crypto-hosts', async () => {
    const testObj = { english: true };
    const encrypted = encryptPayload(JSON.stringify(testObj), TEST_AES_KEY);
    const mock = createMockContext({
      url: PROTECTED_URL,
      body: encrypted,
      env: {
        'aes-crypto-key': TEST_AES_KEY,
        'aes-crypto-hosts': PROTECTED_HOST
      }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const expectedFormatted = JSON.stringify(testObj, null, 2);
    assert.strictEqual(mock.getBodyString(), expectedFormatted);
  });

  // 14. Suporte a Uint8Array retornado por getBody() (Electron IPC)
  await test('Corpo retornado como Uint8Array (Electron IPC) -> Descriptografa com sucesso', async () => {
    const testObj = { status: 'ok', ipc: true };
    const encrypted = encryptPayload(JSON.stringify(testObj), TEST_AES_KEY);
    const u8Buffer = new Uint8Array(Buffer.from(encrypted, 'utf8'));

    const mock = createMockContext({ url: PROTECTED_URL, body: encrypted });
    mock.context.response.getBody = async () => u8Buffer;

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const expectedFormatted = JSON.stringify(testObj, null, 2);
    assert.strictEqual(mock.getBodyString(), expectedFormatted);
  });

  // 15. Base64 com quebras de linha e aspas externas
  await test('Base64 com quebras de linha e aspas externas -> Sanitiza e descriptografa com sucesso', async () => {
    const testObj = { sanitize: true, count: 42 };
    const encrypted = encryptPayload(JSON.stringify(testObj), TEST_AES_KEY);
    const dirtyEncrypted = `\n  "${encrypted.slice(0, 20)}\r\n${encrypted.slice(20)}"\n`;

    const mock = createMockContext({ url: PROTECTED_URL, body: dirtyEncrypted });

    await runWithConsole(mock.mockConsole, async () => {
      await hook(mock.context);
    });

    const expectedFormatted = JSON.stringify(testObj, null, 2);
    assert.strictEqual(mock.getBodyString(), expectedFormatted);
  });

  // 16. Request Hook: Criptografia automática de requisição para host protegido
  await test('Request Hook: JSON no corpo para host protegido -> Criptografa em Base64 e ajusta cabeçalhos', async () => {
    const loginPayload = JSON.stringify({
      clientId: 'cliente-teste',
      username: 'usuario@teste.com'
    });

    const mock = createMockContext({
      url: PROTECTED_URL,
      requestBody: { mimeType: 'application/json', text: loginPayload }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    const bodyText = mock.getRequestBodyText();
    assert.notStrictEqual(bodyText, loginPayload, 'O corpo não deve mais ser o JSON em claro');
    assert(bodyText.length > 0, 'O corpo criptografado não deve ser vazio');

    // Descriptografa com a chave para confirmar integridade
    const { decryptAesPayload } = require('../src/decryptor.js');
    const decResult = decryptAesPayload(bodyText, TEST_AES_KEY);
    assert.strictEqual(decResult.success, true, 'O Base64 gerado deve ser descriptografável pelo decryptor');
    assert.strictEqual(decResult.parsedJson.clientId, 'cliente-teste');

    // Cabeçalhos
    assert.strictEqual(mock.context.request.getHeader('Content-Type'), 'application/json');
    assert.strictEqual(mock.context.request.getHeader('Content-Length'), null, 'Content-Length deve ter sido removido');
  });

  // 17. Request Hook: Sem hosts configurados em aes-cripto-hosts -> NADA é criptografado
  await test('Request Hook: Sem aes-cripto-hosts configurado -> Corpo da requisição permanece inalterado', async () => {
    const rawJson = '{"dados":"teste"}';
    const mock = createMockContext({
      url: PROTECTED_URL,
      requestBody: { mimeType: 'application/json', text: rawJson },
      env: { 'aes-cripto-key': TEST_AES_KEY } // Sem 'aes-cripto-hosts'
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    assert.strictEqual(mock.getRequestBodyText(), rawJson, 'Sem hosts protegidos configurados, nada deve ser modificado');
  });

  // 18. Request Hook: Host local sem estar na lista não é modificado
  await test('Request Hook: JSON para localhost sem estar na lista -> Corpo permanece inalterado', async () => {
    const rawJson = '{"local":true}';
    const mock = createMockContext({
      url: LOCAL_URL,
      requestBody: { mimeType: 'application/json', text: rawJson }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    assert.strictEqual(mock.getRequestBodyText(), rawJson, 'Host local não listado não deve ter o corpo modificado');
  });

  // 19. Request Hook: Host local quando localhost ESTÁ na lista aes-cripto-hosts -> Deve criptografar!
  await test('Request Hook: JSON para localhost quando localhost está em aes-cripto-hosts -> Criptografa com sucesso', async () => {
    const rawJson = JSON.stringify({ localEncrypt: true, port: 8080 });
    const mock = createMockContext({
      url: 'http://localhost:8080/auth/login',
      requestBody: { mimeType: 'application/json', text: rawJson },
      env: { 'aes-cripto-key': TEST_AES_KEY, 'aes-cripto-hosts': 'localhost' }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    const bodyText = mock.getRequestBodyText();
    assert.notStrictEqual(bodyText, rawJson, 'Deve criptografar o body para localhost quando listado');
    const { decryptAesPayload } = require('../src/decryptor.js');
    const decResult = decryptAesPayload(bodyText, TEST_AES_KEY);
    assert.strictEqual(decResult.success, true);
    assert.strictEqual(decResult.parsedJson.localEncrypt, true);
  });

  // 20. Request Hook: Host não protegido não é criptografado
  await test('Request Hook: JSON no corpo para outro host não protegido -> Corpo permanece inalterado', async () => {
    const rawJson = '{"outroHost":true}';
    const mock = createMockContext({
      url: OTHER_HOST_URL,
      requestBody: { mimeType: 'application/json', text: rawJson }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    assert.strictEqual(mock.getRequestBodyText(), rawJson, 'Host externo não protegido não deve ser modificado');
  });

  // 21. Request Hook: URL com template tag {{base_url}}
  await test('Request Hook: URL com tag {{base_url}} -> Resolve template e criptografa normalmente', async () => {
    const rawJson = '{"tag":true}';
    const mock = createMockContext({
      url: '{{base_url}}/auth/login',
      requestBody: { mimeType: 'application/json', text: rawJson },
      env: {
        'base_url': `https://${PROTECTED_HOST}`,
        'aes-cripto-hosts': PROTECTED_HOST,
        'aes-cripto-key': TEST_AES_KEY
      }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    const bodyText = mock.getRequestBodyText();
    assert.notStrictEqual(bodyText, rawJson);
    const { decryptAesPayload } = require('../src/decryptor.js');
    const decResult = decryptAesPayload(bodyText, TEST_AES_KEY);
    assert.strictEqual(decResult.success, true);
    assert.strictEqual(decResult.parsedJson.tag, true);
  });

  // 22. Request Hook: Evita dupla criptografia se o body já for Base64
  await test('Request Hook: Body já em Base64 criptografado -> Ignora e não aplica dupla cifra', async () => {
    const { encryptAesPayload } = require('../src/encryptor.js');
    const encrypted = encryptAesPayload('{"ja_cifrado":true}', TEST_AES_KEY).encryptedBase64;

    const mock = createMockContext({
      url: PROTECTED_URL,
      requestBody: { mimeType: 'application/json', text: encrypted }
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    assert.strictEqual(mock.getRequestBodyText(), encrypted, 'Body já criptografado deve permanecer inalterado');
  });

  // 23. Request Hook: Chave ausente
  await test('Request Hook: Chave ausente no ambiente -> Mantém corpo inalterado e emite aviso', async () => {
    const rawJson = '{"sem_chave":true}';
    const mock = createMockContext({
      url: PROTECTED_URL,
      requestBody: { mimeType: 'application/json', text: rawJson },
      env: { 'aes-cripto-hosts': PROTECTED_HOST } // host protegido mas sem chave
    });

    await runWithConsole(mock.mockConsole, async () => {
      await reqHook(mock.context);
    });

    assert.strictEqual(mock.getRequestBodyText(), rawJson, 'Sem chave o corpo deve permanecer inalterado');
    assert(mock.warns.some(w => w.includes('ausente')), 'Deve emitir aviso de chave ausente');
  });

  origConsole.log('\n====================================================');
  origConsole.log(` Resultados: ${passed} de ${total} testes passaram.`);
  origConsole.log('====================================================\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runTests();
