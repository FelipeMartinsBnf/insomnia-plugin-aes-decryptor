# Insomnia Plugin: AES Crypto & Decryptor

Plugin para o **Insomnia (v13.2.0+)** que automatiza a criptografia bidirecional de requisições e a descriptografia de respostas HTTP para APIs protegidas por **AES-128-ECB**.

Elimina a necessidade de manter scripts *pre-request* ou *after-response* manuais: você escreve JSON limpo no corpo da requisição e visualiza a resposta como JSON formatado diretamente no Insomnia.

---

## 1. O que ele faz

- **No Envio (Request Hook):** Intercepta requisições enviadas aos hosts listados em `aes-cripto-hosts`, criptografa o corpo JSON em **AES-128-ECB Base64** em trânsito e define o cabeçalho `Content-Type: application/json`.
- **Na Resposta (Response Hook):** Intercepta respostas com payload Base64 recebidas dos hosts configurados, descriptografa o conteúdo e exibe como **JSON formatado e indentado (2 espaços)** na aba *Preview*.
- **Sem Hosts Padrão (100% Configurável):** Não há nenhum domínio fixado ou padrão no código. O plugin só atua estritamente nos domínios que você definir em `aes-cripto-hosts` (seja homologação, desenvolvimento, produção ou localhost).
- **Segurança e Auditoria:** Os payloads originais e criptografados são registrados no Console do Insomnia (`Ctrl + Shift + I` -> *Console*) para conferência. A chave de criptografia **nunca** é exposta nos logs.

---

## 2. Regras de Criptografia

| Parâmetro | Valor / Configuração |
| :--- | :--- |
| **Algoritmo** | AES-128 |
| **Modo de Operação** | ECB (Electronic Codebook) |
| **Preenchimento (Padding)** | PKCS7 |
| **Codificação da Chave** | UTF-8 (exatamente 16 bytes) |
| **Formato Criptografado** | String pura em Base64 (sem aspas JSON) |

---

## 3. Como Instalar

Como o plugin é compilado em um único bundle independente (`index.js`), quem for utilizar **não precisa rodar `npm install` nem ter Node.js instalado**.

### Passo 1: Obter os arquivos
Basta clonar o repositório ou copiar a pasta do plugin para dentro do diretório de plugins do Insomnia:

- **Linux:**
  ```bash
  git clone <URL_DO_REPOSITORIO> ~/.config/Insomnia/plugins/insomnia-plugin-aes-decryptor
  ```
- **macOS:**
  ```bash
  git clone <URL_DO_REPOSITORIO> ~/Library/Application\ Support/Insomnia/plugins/insomnia-plugin-aes-decryptor
  ```
- **Windows (PowerShell):**
  ```powershell
  git clone <URL_DO_REPOSITORIO> "$env:APPDATA\Insomnia\plugins\insomnia-plugin-aes-decryptor"
  ```

> **Dica:** No Insomnia, você pode localizar essa pasta clicando em **Preferences** (`Ctrl + ,` ou `Cmd + ,`) -> aba **Plugins** -> botão **"Reveal Plugins Folder"**.

### Passo 2: Ativar no Insomnia
1. No Insomnia, vá em **Preferences** -> aba **Plugins**.
2. Clique no botão **"Reload Plugins"** (ou feche e reabra o Insomnia).
3. O plugin **AES Crypto & Decryptor** aparecerá listado como ativo.

---

## 4. Como Configurar (Variáveis de Ambiente)

No seu **Environment** (Base Environment ou Sub-ambiente ativo) no Insomnia, configure as variáveis abaixo:

```json
{
  "aes-cripto-key": "1234567890abcdef",
  "aes-cripto-hosts": "api.suaempresa.com.br, hml.suaempresa.com.br, localhost"
}
```

### Detalhes das variáveis:

- **`aes-cripto-key` (Obrigatória):** Chave AES de exatamente 16 bytes em UTF-8 (o valor `"1234567890abcdef"` acima é apenas um exemplo fictício; substitua pela chave AES real fornecida pela sua equipe). Também aceita o nome em inglês `aes-crypto-key`.
- **`aes-cripto-hosts` (Obrigatória para ativação):** Lista de domínios/hosts separados por vírgula ou espaço onde o plugin deve atuar.
  - O plugin **somente** atuará nos hosts listados nesta variável. Qualquer host fora da lista passará 100% inalterado.
  - Para testar localmente, basta adicionar `localhost` ou `127.0.0.1` à lista.
  - Suporta curingas/wildcards (ex: `*.suaempresa.com.br`).
  - Também aceita o nome em inglês `aes-crypto-hosts`.

---

## 5. Como Usar no Dia a Dia

1. **Escreva JSON normalmente no corpo da requisição:**
   Na aba **Body**, selecione **JSON** e digite o objeto que deseja enviar:
   ```json
   {
     "clientId": "meu-cliente",
     "username": "usuario@empresa.com",
     "password": "minhasenha"
   }
   ```
2. **Envie a requisição (Send):**
   - Antes do envio, o plugin automaticamente criptografa o JSON para Base64.
   - O servidor recebe o corpo criptografado e retorna a resposta também criptografada.
   - O plugin descriptografa a resposta automaticamente e a exibe formatada como JSON na aba **Preview**.
3. **Não precisa de scripts:**
   - Desative qualquer script de pré-requisição (*pre-request*) ou pós-resposta (*after-response*) que fazia essa criptografia manualmente.
4. **Proteção contra dupla cifra:**
   - Se por qualquer motivo o corpo já estiver criptografado em Base64, o plugin detecta automaticamente e não aplica nova cifra.

---

## 6. Testes Automatizados

Caso queira executar os testes unitários e de integração:

```bash
cd insomnia-plugin-aes-decryptor
npm test
```
