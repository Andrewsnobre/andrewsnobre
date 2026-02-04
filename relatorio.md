
## Relatório de Auditoria — TrainingMegaProtocol (Antes) vs TrainingMegaProtocolFixed (Depois)

**Escopo**

* `TrainingMegaProtocol.sol` 
* `TrainingMegaProtocolFixed.sol` 
* Suíte de regressão: `TrainingMegaProtocolFixed.regression.t.sol` (10 testes)

**Resumo Executivo**
O projeto original foi construído propositalmente com vulnerabilidades típicas de protocolos Web3 (ACL fraca, delegatecall perigoso, replay de assinatura, DoS, erros de oracle e falhas de integração com ERC20).
A versão **Fixed** aplica correções estruturais (ownable consistente, allowlists, EIP-712 + nonce, safe ERC20, sanity checks no oracle, cap de fee, e melhorias anti-DoS).
A suíte de regressão valida que os 10 vetores explorados na versão vulnerável foram mitigados.

---

# 1) Router — Arbitrary Call / Privilege Escalation

### Antes (Vulnerável)

**Local:** `MegaRouter.execute()` e `MegaRouter.multicall()`

* Qualquer caller podia executar `target.call(data)` para qualquer `target`, inclusive chamando funções “onlyOwner” de outros contratos se eles estivessem mal configurados (ou se o Router fosse owner de algo).
* Não existia allowlist nem restrição real de permissão.

**Impacto**

* Execução arbitrária de chamadas com ETH e dados → risco de **drain**, **mudança de parâmetros**, **execução administrativa**.

### Depois (Fixed)

**Mudança aplicada**

* `execute()` e `multicall()` viraram **onlyOwner**
* Foi adicionado `allowedTarget[target]` (allowlist)
* Continua usando `call`, mas agora com governança controlada.

**Patch (o que mostrar ao vivo)**

* “ANTES: qualquer um chama execute(target,data)”
* “DEPOIS: onlyOwner + require(allowedTarget[target])”

**Regressão**

* `test_regression_router_execute_onlyOwner_and_allowlist()`

---

# 2) Router — Controlled Delegatecall (Takeover)

### Antes (Vulnerável)

**Local:** `MegaRouter.execDelegate(plugin, data)`

* `delegatecall` para `plugin` controlado por input e sem allowlist.
* Um plugin malicioso poderia sobrescrever storage do Router (ex: slot do `owner`) e tomar controle.

**Impacto**

* **Takeover total** do Router (mudança de owner / execução arbitrária posterior).

### Depois (Fixed)

**Mudança aplicada**

* `execDelegate()` é **onlyOwner**
* Exige `allowedPlugin[plugin] == true` (allowlist)
* Impede atacante de apontar plugin arbitrário.

**Regressão**

* `test_regression_router_execDelegate_attacker_blocked()`

---

# 3) Airdrop — setSigner sem ACL (Attacker troca signer)

### Antes (Vulnerável)

**Local:** `Airdropper.setSigner(address s)`

* Função sem `onlyOwner` → qualquer um trocava `signer`.

**Impacto**

* Atacante define `signer = attacker` e assina claims arbitrários → drena tokens do airdrop.

### Depois (Fixed)

**Mudança aplicada**

* `Airdropper` virou `OwnableLite`
* `setSigner()` agora é **onlyOwner** + `require(s != address(0))`

**Regressão**

* `test_regression_airdrop_setSigner_onlyOwner()`

---

# 4) Airdrop — Replay de assinatura (sem nonce/domain)

### Antes (Vulnerável)

**Local:** `claim(amount, sig)`

* Digest era `keccak256(abi.encodePacked(user, amount))`
* Sem nonce, sem domain separator, sem chainId, sem verifyingContract.
* Permitindo **replay** do mesmo `sig` em:

  * múltiplas vezes (se `claimed` não bloqueasse)
  * ou em outro contrato/cadeia que use o mesmo formato.

**Impacto**

* Replay / cross-contract replay / cross-chain replay.

### Depois (Fixed)

**Mudança aplicada**

* Adotado **EIP-712** com:

  * domain separator (name, version, chainId, verifyingContract)
  * struct hash `Claim(user, amount, nonce)`
  * `nonces[user]++`

**Regressão**

* `test_regression_airdrop_replay_blocked()`

---

# 5) MegaVault — Oracle misconfig (EOA ou endereço inválido)

### Antes (Vulnerável)

**Local:** `MegaVault.initialize()` e `setOracle()`

* Aceita oracle `address(0)` / EOA / qualquer coisa
* `_calcFee()` chama `oracle.latestAnswer()` sem checar se é contrato real.

**Impacto**

* Inicialização “quebrada” → withdraw pode revertar sempre (DoS) ou comportamento indefinido.

### Depois (Fixed)

**Mudança aplicada**

* `initialize()` exige:

  * `_oracle != 0`
  * `_oracle.code.length > 0` (tem bytecode)
* `setOracle()` idem

**Regressão**

* `test_regression_vault_rejects_EOA_oracle_on_initialize_and_setOracle()`

---

# 6) MegaVault — Oracle edge cases (negativo/overflow/decimals loucos) → DoS

### Antes (Vulnerável)

**Local:** `_calcFee()`

* Faz `uint256 pu = uint256(p)` sem garantir `p > 0`
* `10 ** (18-d)` / `10 ** (d-18)` sem limites → risco de overflow/DoS
* Sem cap de fee → `fee > amount` pode quebrar withdraw (underflow no `shareAmount - fee`).

**Impacto**

* **DoS no withdraw**
* Fee absurda
* Comportamento quebrado com decimals extremos

### Depois (Fixed)

**Mudança aplicada**

* `require(p > 0)`
* `require(d <= 36)`
* cap `pu` e cap final da fee:

  * `MAX_FEE_BPS = 1000` (10%)
  * `fee <= 10%` do amount
* “safety”: se `fee > shareAmount`, ajusta `fee = shareAmount`

**Regressão**

* `test_regression_vault_oracle_abuse_no_DoS_and_fee_bounded()`

---

# 7) MegaVault — Ignorar retorno de token.transfer (ERC20 retorna false)

### Antes (Vulnerável)

**Local:** `withdraw()`

* Chama `token.transfer(...)` mas ignora `bool` de retorno.
* Tokens “estranhos” podem retornar `false` e não transferir → usuário perde shares e não recebe tokens.

**Impacto**

* **Perda de fundos / queima de shares sem pagamento**
* Inconsistência contábil

### Depois (Fixed)

**Mudança aplicada**

* `SafeERC20Lite.safeTransfer` e `safeTransferFrom`:

  * usa low-level `call`
  * reverte se `call` falhar
  * reverte se retornar data e `bool == false`

**Regressão**

* `test_regression_vault_reverts_on_transfer_false()`

---

# 8) Badge — Overwrite de tokenId (re-mint sobrescreve ownerOf)

### Antes (Vulnerável)

**Local:** `BadgeMinter.mint(to, tokenId)`

* Não verifica se `ownerOf[tokenId]` já existe.
* Permitindo sobrescrever “propriedade” do NFT.

**Impacto**

* Roubo/reassign de token já mintado
* `balanceOf` ainda incrementa → inconsistência

### Depois (Fixed)

**Mudança aplicada**

* `require(ownerOf[tokenId] == address(0), "already minted")`

**Regressão**

* `test_regression_badge_no_overwrite()`

---

# 9) Badge — Mint para address(0)

### Antes (Vulnerável)

**Local:** `BadgeMinter.mint(to, tokenId)`

* Aceita `to == address(0)`.

**Impacto**

* NFT “perdido” / supply corrompida / integridade ruim

### Depois (Fixed)

**Mudança aplicada**

* `require(to != address(0), "to=0")`

**Regressão**

* `test_regression_badge_no_to_zero()`

---

# 10) Treasury — Batch DoS (transfer em loop reverte tudo)

### Antes (Vulnerável)

**Local:** `Treasury.payBatch()`

* Usa `tos[i].transfer(amts[i])`
* Se qualquer receiver reverter, **toda a transação reverte** e ninguém recebe (DoS do batch).

**Impacto**

* Um receiver malicioso “trava” o pagamento do lote inteiro.

### Depois (Fixed)

**Mudança aplicada**

* Troca `transfer()` por:

  * `(bool ok,) = tos[i].call{value: amts[i]}("")`
* Se falhar, **não reverte o loop**, só emite `PayFailed`
* Pagamentos válidos continuam.

**Regressão**

* `test_regression_treasury_payBatch_no_DoS()`

---

## Evidência de Correção

* Suíte `TrainingMegaProtocolFixed.regression.t.sol` contém **10 testes** cobrindo os vetores acima.


  1. Rode os exploits no contrato antigo (passam).
  2. Rode a regressão no Fixed (tem que ficar 10/10 PASS).

---
## Por que o Slither “nao pegou os erros” ?

Porque os seus “10 erros” são uma mistura de:

* **padrões detectáveis estaticamente** (delegatecall controlado, retorno ignorado, calls em loop, ether lock)
* **falhas lógicas de negócio** (overwrite de badge, replay, setSigner aberto)
* **cenários dependentes de contexto** (oracle DoS, fee > amount, replay cross-chain)
  E o Slither é **análise estática baseada em heurística**: ele vai apontar o que “parece perigoso pelo código”, mas não prova exploração completa nem pega todas as regras de negócio.

---


