# HubSoft CPE Migrator (Parks ➔ Huawei)

Aplicação web e motor de migração para conversão e atualização automática de seriais de ONTs/CPEs no ERP **HubSoft** (`https://api.dstech.hubsoft.com.br`), facilitando a transição de OLTs Parks para OLTs Huawei.

---

## 🚀 Como Funciona

1. **Conversão de Serial:**
   - **Formato Parks:** `prks00cef6fe` (12 caracteres, prefixo `prks` + 8 dígitos hexadecimais).
   - **Formato Huawei:** `50524B5300CEF6FE` (16 caracteres hexadecimais, onde `50524B53` é a codificação ASCII de `PRKS`).
2. **Atualização no HubSoft:**
   - Desvincula a CPE antiga via endpoint oficial de integração (`/api/v1/integracao/cliente/desvincular_cpe`).
   - Atualiza a camada 2 MAC (`phy_addr`) via endpoint oficial (`/api/v1/integracao/cliente/configurar_autenticacao`), preservando a OLT e interface de conexão existentes.
   - Sincroniza o inventário físico caso a CPE já tenha sido descoberta na porta PON (`/api/v1/integracao/cliente/vincular_cpe`).

---

## 📦 Instalação e Execução (Plug and Play)

### 1. Clonar e Instalar Dependências
```bash
git clone <URL_DO_REPOSITORIO>
cd hubsoft-cpe-migrator
npm install
```

### 2. Configurar o `.env`
Copie o arquivo de exemplo:
```bash
cp .env.example .env
```
Preencha o `.env` com as credenciais padrão de API:
```ini
HUBSOFT_HOST=https://api.dstech.hubsoft.com.br
HUBSOFT_CLIENT_ID=23
HUBSOFT_CLIENT_SECRET=seu_client_secret_aqui
HUBSOFT_USERNAME=usuario_api@provedor.com.br
HUBSOFT_PASSWORD=sua_senha_aqui
PORT=3000
```

> **Nota de Segurança:** O usuário da API **não** precisa de perfil de Administrador, **não** precisa de flag de Técnico e **não** precisa de permissões ampliadas. As permissões de integração normais para o módulo de clientes/serviços são suficientes.

### 3. Iniciar o Servidor
```bash
npm start
```
Abra no navegador: [http://localhost:3000](http://localhost:3000).

---

## 🧪 Testes Automatizados
Para executar a suíte de testes de conversão:
```bash
npm test
```

---

## 🔒 Auditoria
Todas as operações de migração e autenticação geram registros estruturados em JSON Lines em:
`logs/audit.log`
