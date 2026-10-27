const fs = require('fs');
const path = require('path');
const {
  KEY_ENV_NAMES,
  HOSTS_ENV_NAMES,
  PATHS_ENV_NAMES,
  STORE_KEY_AES,
  STORE_HOSTS_KEY
} = require('./constants');

/**
 * Obtém o valor de uma variável a partir do context.request.
 * @param {object} context
 * @param {string} varName
 * @returns {string|null}
 */
function getEnvVar(context, varName) {
  if (!context || !context.request) {
    return null;
  }

  if (typeof context.request.getEnvironmentVariable === 'function') {
    try {
      const val = context.request.getEnvironmentVariable(varName);
      if (val !== undefined && val !== null && String(val).trim().length > 0) {
        return String(val).trim();
      }
    } catch {}
  }

  if (typeof context.request.getEnvironment === 'function') {
    try {
      const env = context.request.getEnvironment();
      if (env && env[varName] !== undefined && env[varName] !== null) {
        const val = String(env[varName]).trim();
        if (val.length > 0) {
          return val;
        }
      }
      // Suporte para escopo de namespace do Insomnia (env._.varName)
      if (env && env._ && env._[varName] !== undefined && env._[varName] !== null) {
        const val = String(env._[varName]).trim();
        if (val.length > 0) {
          return val;
        }
      }
    } catch {}
  }

  return null;
}

/**
 * Resolve tags de template na URL (ex: {{base_url}}/auth/login ou {{ _.base_url }}/auth/login)
 * substituindo-as pelo valor correspondente nas variáveis de ambiente.
 *
 * @param {string} urlStr
 * @param {object} context
 * @returns {string}
 */
function resolveUrl(urlStr, context) {
  if (!urlStr || typeof urlStr !== 'string') {
    return '';
  }

  let resolved = urlStr.trim();

  // Substitui tags de template do Insomnia: {{var_name}} ou {{ _.var_name }}
  if (resolved.includes('{{')) {
    resolved = resolved.replace(/\{\{\s*(?:_\.)?([a-zA-Z0-9_.-]+)\s*\}\}/g, (match, varName) => {
      const val = getEnvVar(context, varName);
      if (val) {
        return val;
      }

      return match;
    });
  }

  return resolved;
}

/**
 * Extrai o hostname em letras minúsculas de uma URL ou string de host.
 * @param {string} urlStr
 * @returns {string|null}
 */
function getHostname(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') {
    return null;
  }

  const trimmed = urlStr.trim();
  try {
    const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    return parsed.hostname.toLowerCase();
  } catch {
    const match = trimmed.match(/^(?:https?:\/\/)?([^/:]+)/i);
    return match ? match[1].toLowerCase() : null;
  }
}

/**
 * Extrai o pathname de uma URL.
 * @param {string} urlStr
 * @returns {string}
 */
function getPathname(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') {
    return '/';
  }

  const trimmed = urlStr.trim();
  try {
    const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    return parsed.pathname;
  } catch {
    const afterProtocol = trimmed.replace(/^https?:\/\/[^/]+/i, '');
    const pathOnly = afterProtocol.split('?')[0].split('#')[0];
    return pathOnly.startsWith('/') ? pathOnly : `/${pathOnly}`;
  }
}

/**
 * Resolve a lista de hosts protegidos a partir da configuração em aes-cripto-hosts (ou aes-crypto-hosts).
 * Não há hosts padrão hardcoded: apenas os hosts explicitamente listados são protegidos.
 *
 * @param {object} context
 * @returns {Promise<string[]>}
 */
async function resolveProtectedHosts(context) {
  const hosts = new Set();

  // 1. Variáveis de ambiente específicas para hosts protegidos (aes-cripto-hosts / aes-crypto-hosts)
  for (const varName of HOSTS_ENV_NAMES) {
    const envVal = getEnvVar(context, varName);
    if (envVal) {
      const parsedList = envVal.split(/[,;\s]+/).filter(Boolean);
      for (const item of parsedList) {
        const h = getHostname(item);
        if (h) {
          hosts.add(h);
        }
      }
    }
  }

  // 2. Fallback no store persistente do plugin
  if (context && context.store && typeof context.store.getItem === 'function') {
    try {
      const storedHosts = await context.store.getItem(STORE_HOSTS_KEY);
      if (storedHosts) {
        const parsed = storedHosts.split(/[,;\s]+/).filter(Boolean);
        for (const item of parsed) {
          const h = getHostname(item);
          if (h) {
            hosts.add(h);
          }
        }
      }
    } catch {}
  }

  return Array.from(hosts);
}

/**
 * Verifica se o hostname pertence à lista de hosts protegidos configurada em aes-cripto-hosts.
 *
 * @param {string} hostname - Hostname da requisição já resolvido.
 * @param {string[]} protectedHosts - Lista de hosts protegidos obtida de aes-cripto-hosts.
 * @returns {boolean}
 */
function isProtectedHost(hostname, protectedHosts) {
  if (!hostname || !Array.isArray(protectedHosts) || protectedHosts.length === 0) {
    return false;
  }

  const h = hostname.toLowerCase().trim();

  for (const protectedHost of protectedHosts) {
    const target = protectedHost.toLowerCase().trim();
    if (!target) continue;

    // Correspondência exata (ex: api.dominio.com ou localhost)
    if (h === target) {
      return true;
    }

    // Suporte a wildcard / sufixo de domínio (ex: *.dominio.com ou .dominio.com)
    if (target.startsWith('*.')) {
      const suffix = target.slice(2);
      if (h.endsWith(suffix) || h === suffix) {
        return true;
      }
    } else if (target.startsWith('.')) {
      if (h.endsWith(target) || h === target.slice(1)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Resolve caminhos específicos para filtragem adicional, se configurados em aes-cripto-paths.
 * @param {object} context
 * @returns {string[]}
 */
function resolvePathFilters(context) {
  for (const varName of PATHS_ENV_NAMES) {
    const val = getEnvVar(context, varName);
    if (val) {
      return val.split(/[,;\s]+/).filter(Boolean);
    }
  }
  return [];
}

/**
 * Verifica se o pathname é permitido pelos filtros configurados.
 * @param {string} pathname
 * @param {string[]} pathFilters
 * @returns {boolean}
 */
function isPathAllowed(pathname, pathFilters) {
  if (!Array.isArray(pathFilters) || pathFilters.length === 0) {
    return true;
  }
  const currentPath = pathname || '/';
  return pathFilters.some((filter) => currentPath.startsWith(filter));
}

/**
 * Tenta obter a chave diretamente do banco local do Insomnia (fallback quando nenhum ambiente está selecionado).
 * @returns {string|null}
 */
function getBaseEnvironmentKeyFallback() {
  try {
    const homeDir = process.env.HOME || process.env.USERPROFILE || '';
    const envDbPath = path.join(homeDir, '.config', 'Insomnia', 'insomnia.Environment.db');
    if (fs.existsSync(envDbPath)) {
      const content = fs.readFileSync(envDbPath, 'utf8');
      const lines = content.trim().split('\n');
      for (const line of lines) {
        try {
          const doc = JSON.parse(line);
          if (doc.data) {
            for (const varName of KEY_ENV_NAMES) {
              if (doc.data[varName]) {
                return String(doc.data[varName]).trim();
              }
            }
          }
        } catch {}
      }
    }
  } catch {}
  return null;
}

/**
 * Resolve a chave de criptografia a partir do ambiente ativo, store do plugin ou fallback do Base Environment.
 * @param {object} context
 * @returns {Promise<string|null>}
 */
async function resolveEncryptionKey(context) {
  // 1. Variáveis do ambiente ativo (Base Environment ou Sub-environment)
  for (const varName of KEY_ENV_NAMES) {
    const key = getEnvVar(context, varName);
    if (key) {
      return key;
    }
  }

  // 2. Store do plugin (persistido em insomnia.PluginData.db)
  if (context && context.store && typeof context.store.getItem === 'function') {
    try {
      const storedKey = await context.store.getItem(STORE_KEY_AES);
      if (storedKey && String(storedKey).trim().length > 0) {
        return String(storedKey).trim();
      }
    } catch {}
  }

  // 3. Fallback: Leitura direta do Base Environment em disco (caso nenhum sub-ambiente esteja selecionado no Insomnia)
  if (!context || !context._isMock) {
    const dbKey = getBaseEnvironmentKeyFallback();
    if (dbKey) {
      return dbKey;
    }
  }

  return null;
}

/**
 * Sanitiza uma string Base64 removendo espaços, quebras de linha e aspas externas se houver.
 * @param {string} str
 * @returns {string}
 */
function sanitizeBase64(str) {
  if (!str || typeof str !== 'string') {
    return '';
  }
  let cleaned = str.trim();
  if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
    cleaned = cleaned.slice(1, -1).trim();
  }
  return cleaned.replace(/[\r\n\s\t\0]/g, '');
}

/**
 * Verifica se a string é uma candidata válida a Base64.
 * @param {string} str
 * @returns {boolean}
 */
function isValidBase64(str) {
  if (!str || typeof str !== 'string') {
    return false;
  }

  const cleaned = sanitizeBase64(str);
  if (cleaned.length === 0 || cleaned.length % 4 !== 0) {
    return false;
  }

  // Se contiver estruturas JSON como chaves {} ou colchetes [], não é Base64 puro
  if (cleaned.startsWith('{') || cleaned.startsWith('[')) {
    return false;
  }

  return /^[A-Za-z0-9+/]+={0,2}$/.test(cleaned);
}

/**
 * Calcula o tamanho real em bytes dos dados representados pela string Base64.
 * @param {string} b64String
 * @returns {number}
 */
function getBase64ByteLength(b64String) {
  if (!b64String || typeof b64String !== 'string') {
    return 0;
  }

  const cleaned = sanitizeBase64(b64String);
  if (cleaned.length === 0 || cleaned.length % 4 !== 0) {
    return 0;
  }

  let padding = 0;
  if (cleaned.endsWith('==')) {
    padding = 2;
  } else if (cleaned.endsWith('=')) {
    padding = 1;
  }

  return (cleaned.length / 4) * 3 - padding;
}

module.exports = {
  resolveUrl,
  getHostname,
  getPathname,
  resolveProtectedHosts,
  isProtectedHost,
  resolvePathFilters,
  isPathAllowed,
  resolveEncryptionKey,
  sanitizeBase64,
  isValidBase64,
  getBase64ByteLength
};
