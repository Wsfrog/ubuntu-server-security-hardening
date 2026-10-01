# Ubuntu Server Hardening

Script Bash para aplicação controlada de medidas de segurança em servidores **Ubuntu 20.04, 22.04 e 24.04**.

O projeto foi desenvolvido com foco em:

- redução da superfície de ataque;
- proteção de acesso SSH;
- configuração de firewall com UFW;
- detecção de tentativas de intrusão com Fail2ban;
- auditoria com auditd;
- endurecimento de parâmetros do kernel;
- aplicação seletiva de políticas AppArmor;
- preservação de configurações existentes;
- geração de backups;
- rollback automático em caso de ausência de confirmação;
- execução previsível, auditável, idempotente e reversível.

> **Importante:** este script altera configurações críticas do sistema e deve ser testado em uma máquina virtual ou ambiente de staging antes de ser utilizado em produção.

---

## Características principais

O script foi projetado para evitar alterações destrutivas por padrão.

Por padrão, ele **não**:

- executa `ufw reset`;
- remove pacotes legados;
- executa `apt autoremove`;
- mascara serviços;
- apaga as regras existentes do auditd;
- habilita todos os perfis AppArmor em modo `enforce`;
- altera a senha ou bloqueia a conta root;
- ativa autenticação por senha no SSH quando não solicitada;
- altera a porta SSH sem que `--ssh-port` seja informado;
- aplica parâmetros agressivos de kernel sem opção explícita.

Antes de realizar as alterações, o script:

1. verifica se está sendo executado como root;
2. valida a versão do Ubuntu;
3. valida o usuário administrativo;
4. verifica a configuração atual do SSH;
5. registra o estado inicial do sistema;
6. cria um backup privado;
7. agenda um rollback automático;
8. solicita confirmação, salvo quando `--yes` é usado;
9. valida arquivos antes de instalá-los;
10. executa verificações pós-aplicação.

---

## Requisitos

### Sistema operacional

- Ubuntu Server 20.04;
- Ubuntu Server 22.04;
- Ubuntu Server 24.04.

Outras distribuições não são suportadas oficialmente.

### Privilégios

A aplicação exige privilégios de root:

```bash
sudo -i
```

ou:

```bash
sudo ./ubuntu-hardening.sh apply --admin-user administrador
```

### Dependências

Durante a execução, o script verifica ferramentas como:

- Bash;
- `apt-get`;
- `systemctl`;
- `sshd`;
- `ssh-keygen`;
- `ufw`;
- `visudo`;
- `auditctl`;
- `augenrules`;
- `apparmor`;
- `python3`;
- `ss`;
- `flock`;
- `findmnt`.

Alguns pacotes de segurança são instalados automaticamente quando as respectivas etapas estão habilitadas.

---

## Instalação

Clone o projeto ou copie o script para o servidor:

```bash
git clone https://github.com/SEU-USUARIO/ubuntu-hardening.git
cd ubuntu-hardening
```

Dê permissão de execução:

```bash
chmod 700 ubuntu-hardening.sh
```

Confirme a sintaxe antes de executar:

```bash
bash -n ubuntu-hardening.sh
```

Opcionalmente, valide com ShellCheck:

```bash
shellcheck ubuntu-hardening.sh
```

> O arquivo deve utilizar finais de linha **LF**. Arquivos enviados com finais de linha Windows/CRLF podem causar erros de sintaxe no Bash.

Para converter um arquivo CRLF:

```bash
sed -i 's/\r$//' ubuntu-hardening.sh
```

---

## Fluxo recomendado

### 1. Executar o modo dry-run

O modo dry-run não aplica alterações. Ele exibe o plano, os diffs e os comandos que seriam executados:

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --dry-run
```

### 2. Aplicar em uma VM ou staging

Mantenha uma sessão SSH aberta e, se possível, um console do hipervisor disponível:

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador
```

O script solicita confirmação antes de iniciar.

### 3. Testar uma nova sessão SSH

Após a aplicação, abra uma nova sessão sem fechar a sessão original:

```bash
ssh administrador@IP_DO_SERVIDOR
```

Se a porta tiver sido alterada:

```bash
ssh -p 2222 administrador@IP_DO_SERVIDOR
```

Teste também comandos administrativos:

```bash
sudo -v
sudo systemctl status
```

### 4. Confirmar o resultado

Depois de verificar o acesso, os serviços e as aplicações:

```bash
sudo ./ubuntu-hardening.sh confirm
```

Esse comando cancela o rollback automático e mantém os backups.

### 5. Reverter as alterações

Caso ocorra algum problema:

```bash
sudo ./ubuntu-hardening.sh rollback
```

O rollback também é executado automaticamente quando o prazo configurado expira e a execução não foi confirmada.

---

## Uso básico

### Aplicação padrão

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador
```

### Alterar a porta SSH

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --ssh-port 2222
```

O script mantém temporariamente a porta anterior liberada no UFW como medida de recuperação. Depois de confirmar o acesso pela nova porta, revise e remova manualmente a regra antiga.

### Restringir SSH a usuários específicos

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --admin-user operador \
  --restrict-ssh-users
```

> Ao usar `--restrict-ssh-users`, usuários não listados podem perder acesso SSH. Faça um inventário dos administradores antes de aplicar.

### Restringir a origem do SSH

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --allow-ssh-from 203.0.113.10/32
```

É possível repetir a opção:

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --allow-ssh-from 203.0.113.10/32 \
  --allow-ssh-from 2001:db8::/32
```

O script verifica se o IP da sessão atual está incluído na lista e solicita confirmação caso contrário.

### Liberar portas adicionais

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --allow-port 443/tcp \
  --allow-port 51820/udp
```

### Configurar rollback de 30 minutos

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --rollback-minutes 30
```

O valor permitido está entre 2 e 120 minutos.

### Execução automatizada

Para automação não interativa:

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --yes
```

Use `--yes` somente quando o plano já tiver sido revisado. O modo automatizado não elimina os riscos operacionais.

---

## Opções disponíveis

### Gerais

| Opção | Descrição |
|---|---|
| `apply` | Aplica o hardening. É o subcomando padrão. |
| `confirm` | Cancela o rollback automático após validação manual. |
| `rollback` | Executa o rollback registrado. |
| `--admin-user USER` | Usuário não-root autorizado para administração. Pode ser repetido. |
| `--dry-run` | Mostra alterações sem aplicá-las. |
| `--yes`, `-y` | Responde automaticamente às confirmações. |
| `--skip STEP` | Ignora uma etapa específica. |
| `--rollback-minutes N` | Define a janela do rollback automático. |
| `--no-auto-rollback` | Desabilita o rollback automático. Não recomendado. |
| `--help` | Exibe a ajuda. |

### SSH

| Opção | Descrição |
|---|---|
| `--ssh-port PORT` | Altera a porta SSH. Sem essa opção, a porta atual é preservada. |
| `--restrict-ssh-users` | Configura `AllowUsers` com os usuários informados. |
| `--allow-password-auth` | Mantém autenticação por senha. Aumenta o risco de ataques de força bruta. |
| `--root-ssh-keys-only` | Permite login root somente com chave, usando `prohibit-password`. |
| `--allow-tcp-forward` | Habilita encaminhamento TCP para bastions e túneis. |
| `--allow-agent-forward` | Habilita encaminhamento do agente SSH. |
| `--skip-ssh-crypto` | Não define explicitamente cifras, MACs e algoritmos KEX. |

### Firewall e Fail2ban

| Opção | Descrição |
|---|---|
| `--allow-port P/proto` | Libera uma porta TCP ou UDP no UFW. Pode ser repetida. |
| `--allow-ssh-from CIDR` | Restringe o SSH a um ou mais IPs/CIDRs. |
| `--ssh-no-ratelimit` | Usa `allow` em vez de `limit` para SSH. |
| `--ufw-reset` | Apaga as regras UFW existentes após confirmação explícita. |
| `--fail2ban-ignoreip IP/CIDR` | Adiciona um IP ou CIDR à lista de exceções do Fail2ban. |
| `--fail2ban-ignore-current-ip` | Ignora o IP atual da sessão no Fail2ban. Usar com cautela. |

### Pacotes

| Opção | Descrição |
|---|---|
| `--full-upgrade` | Executa upgrade geral dos pacotes após confirmação. |
| `--remove-legacy-pkgs` | Remove pacotes legados como telnet, rsh, nis e talk. |

### Kernel e módulos

| Opção | Descrição |
|---|---|
| `--sysctl-extended` | Habilita parâmetros estendidos de kernel. |
| `--disable-ip-forward` | Desabilita encaminhamento IPv4, desde que nenhum papel de roteamento seja detectado. |
| `--disable-ipv6-ra` | Desabilita Router Advertisement IPv6. Pode quebrar SLAAC. |
| `--strict-rpfilter` | Habilita `rp_filter=1`. Pode afetar roteamento assimétrico. |
| `--block-module NAME` | Bloqueia um módulo adicional. Pode ser repetida. |
| `--no-default-modules` | Não bloqueia a lista padrão de módulos. |
| `--block-usb` | Bloqueia `usb-storage` após confirmação. |
| `--block-thunderbolt` | Bloqueia Thunderbolt após confirmação. |

### Contas, arquivos e serviços

| Opção | Descrição |
|---|---|
| `--sudo-io-log` | Ativa log de entrada e saída do sudo. Pode registrar segredos. |
| `--tmout SEC` | Define timeout para shells interativos. |
| `--cron-allow` | Restringe usuários autorizados a usar cron. |
| `--harden-shm` | Configura `/dev/shm` com `nodev,nosuid,noexec`. |
| `--disable-service NAME` | Desabilita um serviço específico. Pode ser repetida. |
| `--mask-services` | Mascara serviços selecionados. Exige confirmação adicional. |

### Auditoria, AppArmor e integridade

| Opção | Descrição |
|---|---|
| `--audit-tune-logs` | Ajusta rotação e tamanho dos logs do auditd. |
| `--audit-immutable` | Adiciona `-e 2`, tornando regras imutáveis até o reboot. |
| `--apparmor-enforce PATH` | Coloca um perfil/programa AppArmor em modo enforce. |
| `--apparmor-complain PATH` | Coloca um perfil/programa AppArmor em modo complain. |
| `--with-aide` | Instala AIDE e cria uma baseline após confirmação. |
| `--with-rkhunter` | Instala rkhunter. |
| `--rkhunter-update` | Atualiza definições do rkhunter usando acesso externo. |
| `--with-lynis` | Executa auditoria Lynis em modo somente leitura. |
| `--collect-reports` | Gera relatórios de arquivos world-writable e SUID/SGID. |

---

## Etapas de execução

O script organiza o processamento nos seguintes passos:

1. configuração inicial e estado global;
2. logging;
3. funções auxiliares;
4. validação de argumentos;
5. pré-verificações do sistema;
6. instalação de pacotes necessários;
7. backup e agendamento do rollback;
8. banners legais;
9. firewall UFW;
10. configuração do OpenSSH;
11. Fail2ban;
12. sysctl e parâmetros do kernel;
13. bloqueio seletivo de módulos;
14. autenticação e sudo;
15. permissões e arquivos críticos;
16. serviços selecionados;
17. auditd;
18. AppArmor;
19. journald;
20. validação de tempo;
21. AIDE, rkhunter e Lynis, quando solicitados;
22. verificações finais e resumo.

As etapas podem ser ignoradas com `--skip`, por exemplo:

```bash
sudo ./ubuntu-hardening.sh apply \
  --admin-user administrador \
  --skip modules \
  --skip services
```

---

## SSH e prevenção de lockout

O SSH é a etapa mais sensível do script.

Antes de alterar a configuração, o script verifica:

- existência do usuário administrativo;
- UID diferente de zero;
- shell de login válido;
- existência do diretório home;
- existência de uma chave pública utilizável;
- tipo e tamanho mínimo da chave;
- permissões do home, diretório `.ssh` e arquivo de chaves;
- porta SSH atual;
- suporte dos algoritmos criptográficos pelo OpenSSH local.

A configuração final é validada com:

```bash
sshd -t
sshd -T
```

Depois do reinício, o script verifica se a porta alvo está escutando. Se o SSH não voltar, o rollback imediato é acionado.

Mesmo com essas proteções, mantenha:

- a sessão SSH atual aberta;
- uma segunda sessão pronta para teste;
- acesso via console do provedor ou hipervisor;
- uma cópia do backup fora do servidor.

---

## Backup e rollback

Os arquivos são armazenados em:

```text
/var/backups/ubuntu-hardening-YYYYMMDD-HHMMSS/
```

Os logs ficam em:

```text
/var/log/ubuntu-hardening/
```

O estado pendente do rollback fica em:

```text
/var/lib/ubuntu-hardening/pending
```

O rollback automático é implementado com um timer transitório do systemd. Se a execução não for confirmada dentro do prazo, o script tenta restaurar:

- arquivos de configuração;
- permissões alteradas;
- parâmetros sysctl;
- estado anterior dos serviços modificados;
- estado do AppArmor;
- configuração do SSH;
- arquivos do UFW;
- arquivos de regras do auditd;
- configuração do journald.

Pacotes instalados não são removidos automaticamente durante o rollback. Upgrades de pacotes também não são revertidos automaticamente.

Para consultar os arquivos disponíveis:

```bash
sudo ls -la /var/backups/ubuntu-hardening-*/
```

Para rollback usando um backup específico:

```bash
sudo ./ubuntu-hardening.sh rollback \
  --backup-dir /var/backups/ubuntu-hardening-YYYYMMDD-HHMMSS
```

---

## Validação pós-execução

Execute os comandos abaixo após o hardening:

```bash
sudo sshd -t
sudo sshd -T | grep -Ei '^(port|permitrootlogin|passwordauthentication|allowusers|ciphers|macs|kexalgorithms) '
```

```bash
sudo ss -tlnp | grep -E 'sshd|ssh'
```

```bash
sudo ufw status verbose
sudo ufw show added
```

```bash
sudo fail2ban-client ping
sudo fail2ban-client status sshd
```

```bash
sudo sysctl -a 2>/dev/null | grep -E 'kptr_restrict|dmesg_restrict|accept_redirects|ptrace_scope'
```

```bash
sudo auditctl -s
sudo auditctl -l | head -n 30
```

```bash
sudo aa-status | head -n 20
```

```bash
sudo visudo -c
sudo systemctl is-active auditd fail2ban ufw apparmor
```

```bash
timedatectl show -p NTPSynchronized --value
```

Se disponível:

```bash
sudo lynis audit system --quick
```

---

## Códigos de saída

| Código | Significado |
|---:|---|
| `0` | Execução concluída sem falhas registradas. |
| `1` | Execução abortada ou falha crítica. |
| `2` | Uso inválido ou argumento incorreto. |
| `3` | Execução concluída com falhas não críticas. |

---

## Considerações de segurança

Este script melhora a postura de segurança do sistema, mas não substitui uma arquitetura completa de segurança.

Para ambientes expostos à Internet, considere também:

- MFA ou chaves FIDO2 para SSH;
- bastion host ou VPN administrativa;
- envio de logs para SIEM remoto;
- monitoramento de integridade fora do host;
- backups testados e offline;
- criptografia de disco com LUKS;
- segmentação de rede;
- gerenciamento centralizado de identidades;
- atualização controlada de kernel e pacotes;
- políticas de resposta a incidentes;
- revisão periódica com Lynis, OpenSCAP ou CIS Benchmark.

### Atenção ao AIDE e rkhunter

A baseline do AIDE e as propriedades do rkhunter representam o estado atual do host. Elas não comprovam que a máquina está íntegra.

Crie baselines somente em um sistema confiável e mantenha cópias externas, preferencialmente somente leitura.

### Atenção aos logs do sudo

A opção `--sudo-io-log` pode registrar dados digitados durante sessões administrativas, incluindo tokens, senhas e informações sensíveis. Use essa opção somente após avaliar os requisitos de privacidade e retenção de logs.

### Atenção ao `/dev/shm`

A opção `--harden-shm` pode quebrar navegadores, JITs, bancos de dados, containers e outras aplicações que executam código em memória compartilhada.

### Atenção a serviços

Nunca desabilite serviços sem confirmar que eles não são necessários para a aplicação. O script mostra dependências conhecidas antes da alteração, mas a decisão final depende do administrador do ambiente.

---

## Idempotência

O script tenta ser idempotente:

- arquivos iguais não são regravados;
- configurações existentes são preservadas sempre que possível;
- serviços não são alterados sem opção explícita;
- regras de auditoria existentes são preservadas;
- baselines existentes do AIDE não são sobrescritas;
- o estado inicial é registrado antes das alterações.

Ainda assim, cada execução deve ser revisada, principalmente quando houver alterações de versão do Ubuntu, OpenSSH, systemd ou auditd.

---

## Estrutura de diretórios gerados

```text
/var/lib/ubuntu-hardening/
└── pending

/var/log/ubuntu-hardening/
├── hardening-YYYYMMDD-HHMMSS.log
└── reports/

/var/backups/ubuntu-hardening-YYYYMMDD-HHMMSS/
├── files/
├── state-before/
├── manifest.txt
├── rollback.sh
├── rollback.log
├── services_state
├── sysctl_prev
└── perms_prev
```

---

## Testes recomendados

Antes de usar em produção, teste pelo menos:

- execução com `--dry-run`;
- usuário inexistente;
- usuário root como administrador;
- porta SSH inválida;
- CIDR inválido;
- porta adicional inválida;
- servidor com `ssh.socket` ativo;
- servidor com Docker ou Kubernetes;
- servidor com regras UFW existentes;
- servidor com regras auditd existentes;
- servidor com múltiplos administradores;
- servidor sem chave SSH válida;
- mudança de porta SSH;
- rollback automático;
- rollback manual;
- execução repetida;
- interrupção durante uma etapa;
- falha simulada de `sshd -t`;
- falha de carregamento do auditd;
- serviços críticos em execução;
- aplicação que depende de `/dev/shm` executável.

---

## Limitações conhecidas

- O rollback não desfaz instalação ou upgrade de pacotes.
- Logs locais podem ser apagados por um invasor que obtenha privilégios elevados.
- O script não implementa MFA.
- O script não configura envio remoto de logs.
- A alteração de regras do UFW pode afetar ambientes Docker, pois portas publicadas pelo Docker podem contornar regras tradicionais.
- Parâmetros como `rp_filter`, `accept_ra`, `ip_forward` e `noexec` podem ser incompatíveis com funções específicas do servidor.
- O comportamento de alguns serviços pode variar conforme a versão do Ubuntu e os pacotes instalados.

---

## Aviso de responsabilidade

Este projeto é uma ferramenta de administração e hardening. O operador é responsável por:

- revisar o plano antes da execução;
- testar em ambiente controlado;
- manter acesso de recuperação;
- validar compatibilidade com a aplicação;
- manter backups independentes;
- acompanhar os logs e os resultados;
- adaptar as políticas aos requisitos do ambiente.

Nenhum script de hardening garante segurança absoluta. A proteção efetiva depende também de arquitetura, processos, monitoramento, atualização e resposta a incidentes.
