# Vulnerabilidade técnica explorada pelo EternalBlue (SMBv1, MS17-010)

Nota metodológica: pesquisa feita em 15/11/2026. Dados de NVD (API JSON, `lastModified` de 2026) e do catálogo CISA KEV (versão 2026.11.13, 1781 entradas) foram lidos diretamente dos feeds oficiais. Fontes secundárias e terciárias estão marcadas como tal. Itens "Inferências" são interpretação do pesquisador, não afirmação das fontes. Termos técnicos permanecem em inglês.

---

## 1. Quais CVEs compõem o MS17-010 e qual(is) o EternalBlue usa (descrições oficiais, CVSS, CWE)

### Takeaway
O boletim MS17-010 (14/03/2017, KB4013389) cobre seis CVEs: CVE-2017-0143, -0144, -0145, -0146 e -0148 (RCE no SMBv1) e CVE-2017-0147 (information disclosure). O EternalBlue é associado de forma consistente por fontes secundárias ao CVE-2017-0144, mas nem o boletim da Microsoft nem o post do MSRC sobre o vazamento trazem o mapeamento exploit-para-CVE; esse mapeamento vem de Check Point, Wikipedia (terciária) e outros. O módulo Metasploit do EternalBlue cita os seis CVEs.

### Cited Findings
- Boletim MS17-010 "Security Update for Microsoft Windows SMB Server (4013389)", publicado em 14/03/2017, versão 1.0, rating Critical para todas as versões suportadas. Resumo: o mais grave permite remote code execution "if an attacker sends specially crafted messages to a Microsoft Server Message Block 1.0 (SMBv1) server". A correção atua "correcting how SMBv1 handles specially crafted requests" — [Microsoft Learn, MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Texto do boletim: "in most situations, an unauthenticated attacker could send a specially crafted packet to a targeted SMBv1 server". Microsoft "has not identified any mitigating factors". Workaround: desabilitar SMBv1 (KB2696547) — [Microsoft Learn, MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Tabela do boletim: título "Windows SMB Remote Code Execution Vulnerability" para CVE-2017-0143, -0144, -0145, -0146 e -0148; "Windows SMB Information Disclosure Vulnerability" para CVE-2017-0147 (severidade Important). Na data do boletim, "Publicly disclosed: No" e "Exploited: No" para todos — [Microsoft Learn, MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- NVD CVE-2017-0144: publicado 17/03/2017. Descrição: "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka 'Windows SMB Remote Code Execution Vulnerability.' This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148." — [NVD CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) (dados lidos via API: [NVD API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0144))
- As descrições NVD de CVE-2017-0143, -0145, -0146 e -0148 são idênticas, apenas trocando a lista "different from" — [NVD 0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143), [NVD 0145](https://nvd.nist.gov/vuln/detail/CVE-2017-0145), [NVD 0146](https://nvd.nist.gov/vuln/detail/CVE-2017-0146), [NVD 0148](https://nvd.nist.gov/vuln/detail/CVE-2017-0148)
- CVE-2017-0147 (NVD): "allows remote attackers to obtain sensitive information from process memory via a crafted packets, aka 'Windows SMB Information Disclosure Vulnerability.'" — [NVD CVE-2017-0147](https://nvd.nist.gov/vuln/detail/CVE-2017-0147)
- Scores NVD (status "Analyzed", dados da API em 15/11/2026):

  | CVE | CVSS v3.1 (NVD) | Vetor v3.1 | CVSS v2 (NVD) | Vetor v2 | CWE (NVD) |
  |---|---|---|---|---|---|
  | CVE-2017-0143 | 8.8 High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 9.3 High | AV:N/AC:M/Au:N/C:C/I:C/A:C | NVD-CWE-noinfo |
  | CVE-2017-0144 | 8.8 High | idem | 9.3 High | idem | NVD-CWE-noinfo |
  | CVE-2017-0145 | 8.8 High | idem | 9.3 High | idem | NVD-CWE-noinfo |
  | CVE-2017-0146 | 8.8 High | idem | 9.3 High | idem | NVD-CWE-noinfo |
  | CVE-2017-0147 | 7.5 High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 4.3 Medium | AV:N/AC:M/Au:N/C:P/I:N/A:N | NVD-CWE-noinfo |
  | CVE-2017-0148 | 8.1 High | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.3 High | AV:N/AC:M/Au:N/C:C/I:C/A:C | CWE-20 |

  Fonte dos valores: NVD API 2.0 (ex.: [CVE-2017-0144](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0144), [0148](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0148)); páginas HTML correspondentes em nvd.nist.gov/vuln/detail/CVE-2017-014x. O CNA secundário (134c704f-...) repete os mesmos scores v3.1. Datas `published` NVD: 17/03/2017 para todos os seis; `lastModified` de CVE-2017-0144/0145 = 14/08/2026, dos demais = 17/06/2026.
- O módulo Metasploit `ms17_010_eternalblue` ("Metasploit port of the Equation Group ETERNALBLUE exploit, part of the FuzzBunch toolkit") lista como referências os seis CVEs (0143 a 0148). Descrição técnica do módulo: buffer overflow em um `memmove` em `Srv!SrvOs2FeaToNt`; o tamanho é calculado em `Srv!SrvOs2FeaListSizeToNt`, "where a DWORD is subtracted into a WORD"; o kernel pool é "groomed" para o overflow sobrescrever um buffer SMBv1; o desvio do fluxo termina em `srvnet!SrvNetWskReceiveComplete`. Data de disclosure: 14/03/2017 — [Rapid7 DB, ms17_010_eternalblue](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)
- Check Point liga o exploit ao boletim MS17-010 e ao CVE-2017-0144 — [Check Point Research, "EternalBlue – Everything There Is To Know"](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- Wikipedia (terciária) identifica o EternalBlue como CVE-2017-0144 — [Wikipedia, EternalBlue](https://en.wikipedia.org/wiki/EternalBlue)
- Microsoft Security Update: o post do MSRC sobre o vazamento do ShadowBrokers lista EternalBlue como "Addressed by MS17-010" sem número de CVE na tabela — [Microsoft MSRC, "Protecting customers and evaluating risk" (abril/2017)](https://www.microsoft.com/en-us/msrc/blog/2017/04/protecting-customers-and-evaluating-risk)
- Discrepância CWE: o CISA KEV registra CWE-20 para CVE-2017-0143, -0144, -0145, -0146 e -0148, e CWE-200 para -0147 — [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json); já o NVD atualmente registra NVD-CWE-noinfo para 0143 a 0147 e CWE-20 apenas para 0148 — [NVD API CVE-2017-0144](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0144)
- Discrepância de escopo no briefing: CERT/CC VU#867968 NÃO é o MS17-010; o Vulnerability Note com esse ID trata de CVE-2017-0016 (SMB2 TREE_CONNECT Response, DoS no cliente em mrxsmb20.sys, corrigido em MS17-012) — [CERT/CC VU#867968](https://www.kb.cert.org/vuls/id/867968)

### Inferências
- O CVSS v3.1 do NVD usa PR:L (privileges required: low) para 0143-0146, o que difere da narrativa popular "totalmente não autenticado". Isso é coerente com Worawit/Rapid7 (EternalBlue precisa ao menos de acesso a IPC$, que em Windows < 8 aceita sessão anônima/guest; ver seção 3), mas o NVD não explica a escolha. É interpretação.
- O CVSS v2 (AC:M, Au:N) reflete "sem autenticação"; a divergência v2 vs v3.1 quanto à autenticação é, portanto, um ponto didático útil.
- Para o grupo: dizer "o EternalBlue explora o CVE-2017-0144 (MS17-010)" é a formulação mais segura, acrescentando que o patch MS17-010 corrige seis CVEs e que o NVD descreve 0143-0146 e 0148 com textos praticamente idênticos (a descrição NVD não permite distinguir tecnicamente cada bug).

### Gaps
- Não encontrei, em fonte primária da Microsoft (boletim ou post do MSRC), um mapeamento explícito "EternalBlue = CVE-2017-0144". O mapeamento vem de Check Point, Wikipedia e agregadores. A página Security Update Guide do MSRC (msrc.microsoft.com/update-guide) não foi acessada.
- A página do MITRE/CVE.org (cve.org/CVERecord?id=CVE-2017-0144) não foi lida diretamente nesta sessão (o boletim da Microsoft linka para ela). A descrição NVD é a mesma texto do registro CVE da MITRE, mas isso é suposição não verificada.
- As páginas HTML do NVD retornaram vazias via WebFetch (renderizadas por JS); os dados vêm da API JSON oficial.

---

## 2. Contexto: SMB/CIFS/SMBv1, portas 445/139, NT Trans/Trans2, drivers srv.sys/srvnet.sys

### Takeaway
O alvo é o servidor SMBv1 do kernel Windows (driver `srv.sys`, com `srvnet.sys` no transporte), alcançado via TCP 445 (e 139 sobre NetBIOS). O bug está no tratamento de transações SMB1 (`SMB_COM_NT_TRANSACT`, `SMB_COM_TRANSACTION2` e seus *secondary* requests), não em SMBv2/3.

### Cited Findings
- SMBv2 foi introduzido no Windows Vista/Server 2008 e SMBv3 no Windows 8/Server 2012. SMBv1 é recomendado a não ser usado ("we strongly encourage you not to use it"). SMBv1 não vem instalado por padrão no Windows 11, Windows Server 2019+ e (exceto Home/Pro) no Windows 10, e deixou de ser instalado por padrão desde o Windows 10 Fall Creators Update (1709) — [Microsoft Learn, Detect, enable and disable SMBv1/v2/v3](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- Em sistemas Windows anteriores, SMBv1 server está habilitado por padrão (a chave `SMB1` em `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` não existe e o padrão é "Enabled") — [Microsoft Learn, mesma página](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- Portas: a orientação pública da época recomendava bloquear UDP 137/138 e TCP 139/445 (via NCSC-UK, resumindo orientação Microsoft do WannaCry) — [NCSC UK, WannaCry guidance for enterprise administrators](https://www.ncsc.gov.uk/guidance/ransomware-wannacry-guidance-enterprise-administrators-1) (fonte conhecida apenas via snippet de busca; não lida na íntegra)
- Check Point descreve que `SMB_COM_TRANSACTION2` carrega o tamanho dos dados em um WORD (máx. 0xFFFF) e `SMB_COM_NT_TRANSACT` em um DWORD (máx. 0xFFFFFFFF), e que o servidor não valida qual comando iniciou a transação — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- Rapid7 cita o código envolvido: funções em `Srv!` (srv.sys: `SrvOs2FeaToNt`, `SrvOs2FeaListSizeToNt`) e `srvnet!SrvNetWskReceiveComplete` (srvnet.sys) — [Rapid7 DB](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)
- Worawit: o EternalBlue exige apenas acesso ao share IPC$ (sem named pipe); Windows Vista+ bloqueia por padrão acesso anônimo a qualquer named pipe; Windows 8+ bloqueia por padrão acesso anônimo a IPC$ — [GitHub worawit/MS17-010](https://github.com/worawit/MS17-010)
- O vulnerabilidade está no servidor SMBv1; a documentação do boletim fala apenas em "SMBv1 server" — [Microsoft Learn, MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)

### Inferências
- Para a apresentação: o bug é no lado servidor (listener em 445/139). Máquinas sem SMBv1 server habilitado, ou sem 445 alcançável, não são exploráveis por este vetor. Isso decorre do boletim (workaround = desabilitar SMBv1).
- O fato de o `srv.sys` rodar em kernel mode e processar o pacote antes de qualquer verificação de autenticação robusta explica o impacto SYSTEM; é uma inferência a partir de o código executar em kernel (ver seção 3).

### Gaps
- Não consegui abrir a especificação [MS-SMB] / [MS-CIFS] (URL tentada retornou 404). Descrição formal de NT_TRANSACT/Trans2 e das portas deve ser conferida em learn.microsoft.com/openspecs/windows_protocols/ms-smb e ms-cifs.
- Não li documentação Microsoft específica descrevendo `srvnet.sys`; o papel dele vem de Check Point/Rapid7.

---

## 3. Causa raiz em profundidade (SrvOs2FeaListSizeToNt, truncamento WORD/DWORD, transaction mismatch, pool grooming, MDL, shellcode)

### Takeaway
O bug central é um erro de cálculo de tamanho em `SrvOs2FeaListSizeToNt` (srv.sys) ao converter uma lista FEA (File Extended Attributes, formato OS/2) para o formato NT: o tamanho é tratado como WORD (16 bits) em vez de DWORD (32 bits), de modo que o buffer alocado no non-paged pool é menor que o número de bytes copiados, gerando um out-of-bounds write. Esse bug só é alcançável com tamanho >64 KB porque um segundo bug (confusão entre NT_TRANSACT e TRANSACTION2_SECONDARY) permite entregar um DWORD onde o parser espera WORD; o exploit completo ainda depende de grooming do pool e da sobrescrita de estruturas do srvnet para obter execução de código em kernel.

### Cited Findings
- **Bug A (srv.sys, cast errado):** `SrvOs2FeaListSizeToNT` "shrinks" `SizeOfListInBytes` quando um registro FEA estoura, mas na prática aumenta o tamanho; a redução escreve apenas a word baixa de um DWORD ("The 2 most significant bytes remain untouched"). O valor de retorno (tamanho do buffer `NtFeaList`) é calculado com o tamanho reduzido, enquanto a cópia usa o valor ampliado, o que gera um "Out of Bound write". Funções relacionadas: `SrvOs2FeaListToNt` (aloca o buffer no non-paged pool e itera a lista) e `SrvOs2FeaToNT` (converte cada registro, acrescentando `NextEntryOffset` e alinhamento de 4 bytes) — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- Rapid7 resume: overflow em `memmove` de `Srv!SrvOs2FeaToNt`, com o tamanho vindo de `Srv!SrvOs2FeaListSizeToNt`, "where a DWORD is subtracted into a WORD" — [Rapid7 DB](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)
- zerosum0x0/RiskSense (junho/2017): o código vulnerável está no caminho `Srv!SrvOs2FeaListToNt` (com `SrvOs2FeaListSizeToNt` inlined no Windows 10 1511); a causa é um erro matemático que gera buffer overflow; "The fix replaced 16-bit registers with 32-bit versions" e acrescentou instruções/mitigações extras nos caminhos até esse ponto. O post não cita explicitamente "16-bit truncation", só o patch (a leitura de truncamento 16->32 é consistente com Check Point e Rapid7) — [zerosum0x0, "ETERNALBLUE: Exploit Analysis and Port to Microsoft Windows 10" (07/06/2017)](https://zerosum0x0.blogspot.com/2017/06/eternalblue-exploit-analysis-and-port.html). Whitepaper associado (RiskSense/Jenna Magius): https://jennamagius.keybase.pub/EternalBlue_RiskSense-Exploit-Analysis-and-Port-to-Microsoft-Windows-10.pdf (URL listada no post; não consegui baixar — host não resolveu)
- **Bug B (transaction type mismatch):** não há validação do comando que iniciou a transação; o parsing segue "the last transaction type". Um `SMB_COM_NT_TRANSACT` seguido de `SMB_COM_TRANSACTION2_SECONDARY` faz o tamanho DWORD ser interpretado como WORD, o que dispara o Bug A — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- **Bug C (alocação controlada no non-paged pool, via Session Setup):** uma requisição de Extended Security (WordCount 12) enviada sem o flag `FLAGS2_EXTENDED_SECURITY` é interpretada como NT Security (WordCount 13); `GetNtSecurityParameters` lê `ByteCount` do offset errado, o que permite alocação controlada no non-paged pool. Check Point o descreve como peça auxiliar de heap grooming, não como bug de execução de código por si só — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/) (o repositório do Worawit tem um script `npp_control.py` sobre "nonpaged-pool allocation control through session setup" — [GitHub worawit/MS17-010](https://github.com/worawit/MS17-010))
- **Pool grooming:** Check Point descreve um processo em 9 passos: abrir transações SMBv1 e várias conexões SMBv2/`srvnet`, criar um "buraco" no pool com o Bug C e preenchê-lo com a alocação `NtFea` que sofre overflow; o pacote secundário final transborda o chunk vizinho do `srvnet` — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/). O README do RiskSense-Ops confirma o padrão: vários requests de groom SMB2 com headers nulos e shellcode, "free hole" via session setups, e o pacote final SMB1 Trans2 com offsets fixos (sugere que IDS foquem nesse último pacote) — [GitHub RiskSense-Ops/MS17-010](https://github.com/RiskSense-Ops/MS17-010)
- **Estruturas srvnet:** `SRVNET_HEADER` contém `pSrvNetWskStruct` (ponteiro para `SRVNET_RECV`) e `pMdl1` (ponteiro para MDL). `SRVNET_RECV` contém `HandlerFunction`, chamado quando a conexão fecha — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- **Primitiva write-what-where via MDL:** "Controlling the MDL lets you 'write-what-where' the primitive"; sobrescrever `StartVA` redireciona dados do cliente para um endereço escolhido — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- **Execução de shellcode (versão original, Windows < 8):** o alvo é o HAL heap (`0xffffffff'ffd00000` em x64, `0xffd00000` em x86), "executable in Windows versions prior to Windows 8 / Server 2012"; o `HandlerFunction` falso executa o shellcode quando as conexões fecham; o payload é o DoublePulsar — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- **DoublePulsar (zerosum0x0, abril/2017):** o shellcode carrega código x86 e x64; localiza `ntoskrnl` varrendo a partir da IDT (KPCR), resolve funções por hash (`ZwQuerySystemInformation`, `ExAllocatePool`, `ExFreePool`), localiza o `srv.sys` por `SystemModuleInformation` e substitui a entrada 14 (offset 0x70) de `SrvTransaction2DispatchTable`, guardando o ponteiro original `SrvTransactionNotImplemented`. Canal de comando via requests Trans2 especiais, com o opcode no campo Timeout (0x23 ping, 0xc8 exec, 0x77 kill) e a resposta sinalizada por delta no MultiplexID (0x10 sucesso, 0x20 parâmetros inválidos, 0x30 falha de alocação). Payloads são enviados em chunks de 4096 bytes em pacotes SESSION_SETUP, XOR com chave derivada da `SMB Signature1`. O autor nota que, por viver em `srv.sys`, evita detecção do PatchGuard (sem confirmar para versões mais novas) — [zerosum0x0, DoublePulsar](https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html)
- Confiabilidade/risco: o EternalBlue "has higher chance of crashing the target than the others"; módulo Metasploit com ranking "Average" e advertência de BSOD/reboot — [GitHub worawit/MS17-010](https://github.com/worawit/MS17-010); [Rapid7 DB](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)
- O repositório do Worawit contém `BUG.txt` com "bug detail and some analysis" sobre nove bugs; `eternalblue_exploit7.py` (Windows 7/2008), `eternalblue_exploit8.py` (Windows 8/2012 x64) e `eternalblue_poc.py` (PoC do overflow) — [GitHub worawit/MS17-010](https://github.com/worawit/MS17-010). Resumo (de alto nível) do BUG.txt: os nove bugs incluem info leaks (memória não inicializada, leituras além do buffer), erros de tamanho/inteiros, confusão entre dois formatos de session setup, modificação de transações multi-parte durante o processamento, e out-of-bounds write via mecanismo de transações — fonte: [BUG.txt, raw](https://raw.githubusercontent.com/worawit/MS17-010/master/BUG.txt) (resumo obtido via ferramenta que recusou reproduzir o texto integral; ver Gaps)

### Inferências
- Em termos de classes de falha, a cadeia pode ser descrita como: (1) integer truncation (CWE-197, 32->16 bits) leva a (2) heap/pool buffer overflow (CWE-122/CWE-787), com (3) type confusion de transação como pré-condição de alcance. Essa classificação CWE é do pesquisador; NVD/KEV só usam NVD-CWE-noinfo/CWE-20.
- Execução em SYSTEM: como o código roda em kernel (Ring 0) dentro de `srv.sys`/`srvnet.sys`, o shellcode herda privilégio total; o DoublePulsar injeta payload em userland a partir do kernel. Check Point e zerosum0x0 mostram execução em kernel; "SYSTEM" é consequência lógica, não frase literal das fontes.
- "Wormable": exploit não autenticado (ou anônimo via IPC$), remoto, sem interação do usuário, em serviço ligado por padrão em 445 em redes internas — razão pela qual WannaCry/NotPetya o usaram para propagação (ver Wikipedia, abaixo). Rotular como "wormable" é interpretação; a Wikipedia cita o uso no WannaCry de 12/05/2017 e NotPetya de 27/06/2017 — [Wikipedia, EternalBlue](https://en.wikipedia.org/wiki/EternalBlue)
- Há uma pequena inconsistência didática a explicar: o exploit original (FuzzBunch) é limitado a Windows < 8 por depender de memória executável no HAL heap; a vulnerabilidade em si existe em versões posteriores (boletim) e foi explorada em Windows 8/2012 e Windows 10 em portes públicos (Worawit `eternalblue_exploit8.py`; zerosum0x0/RiskSense para Windows 10).

### Gaps
- Não consegui ler o `BUG.txt` do Worawit na íntegra (a ferramenta de fetch recusou reproduzir). O grupo deve ler diretamente https://github.com/worawit/MS17-010/blob/master/BUG.txt para tamanhos exatos, layout do pool e detalhes de MDL/`Transaction`.
- O whitepaper RiskSense/zerosum0x0 (PDF) e o post "MS17-010 EternalBlue's Large Non-Paged Pool Overflow in SRV Driver" (Trend Micro/Risk Based Security, RiskSense) não foram lidos. A estrutura `SRVNET_BUFFER_HDR` especificamente não foi confirmada em nenhuma fonte lida (Check Point usa `SRVNET_HEADER`; verificar nome nos PDFs originais).
- Kaspersky, Trend Micro, Risk Based Security, MalwareTech e papers acadêmicos IEEE/ACM não foram consultados por limite de tempo/ferramentas.
- O post de zerosum0x0 em https://zerosum0x0.blogspot.com/2017/06/eternalblue.html retornou 404; usei a URL correta (`...eternalblue-exploit-analysis-and-port.html`).
- Imagens (pseudocódigo/capturas) do artigo do Check Point não puderam ser lidas; apenas o texto.

---

## 4. Versões do Windows afetadas e por que é não autenticado, remoto, wormable e SYSTEM

### Takeaway
O boletim MS17-010 lista Vista SP2, Server 2008/2008 R2, Windows 7, 8.1, RT 8.1, Server 2012/2012 R2, Windows 10 (RTM, 1511, 1607) e Server 2016 como afetados com severidade Critical. XP, Server 2003 e Windows 8 (não 8.1) estavam fora de suporte e só receberam patch de emergência em maio de 2017 (após o WannaCry). Exploits públicos clássicos (FuzzBunch) miraram Windows < 8; portes posteriores cobriram Windows 8/10.

### Cited Findings
- Software afetado no boletim (RCE em 0143-0146, 0148; 0147 = Info Disclosure): Windows Vista SP2 (x86/x64), Server 2008 (x86/x64/Itanium, incl. Server Core), Windows 7 SP1, Server 2008 R2 SP1, Windows 8.1, Server 2012 e 2012 R2, Windows RT 8.1, Windows 10 (RTM, 1511, 1607) e Server 2016, com as KBs 4012598, 4012212, 4012215, 4012213, 4012216, 4012214, 4012217, 4012606, 4013198, 4013429 — [Microsoft Learn, MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- O boletim diz: "Versions or editions that are not listed are either past their support life cycle or are not affected" — [Microsoft Learn, MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Microsoft (MSRC, 13/05/2017): clientes em versões suportadas teriam recebido o MS17-010 em março; para plataformas só em custom support (XP, Server 2003, Windows 8) a Microsoft tornou a atualização amplamente disponível; "Customers running Windows 10 were not targeted by the attack today" (WannaCrypt) — [Microsoft MSRC, Customer Guidance for WannaCrypt attacks](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks)
- NCSC-UK sumariza as downloads de emergência: Windows Server 2003 SP2, Windows XP SP2/SP3, XP Embedded SP3, Windows 8 (x86/x64) — [NCSC UK](https://www.ncsc.gov.uk/guidance/ransomware-wannacry-guidance-enterprise-administrators-1) (via snippet de busca)
- Check Point: "EternalBlue works on all Windows versions prior to Windows 8" (afirmação sobre o exploit original, não sobre a vulnerabilidade) — [Check Point Research](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- Worawit README: EternalBlue "Windows < 8 in all configurations, if TCP 445 is reachable"; EternalBlue só precisa de IPC$; script para Windows 8/2012 x64 existe (`eternalblue_exploit8.py`) — [GitHub worawit/MS17-010](https://github.com/worawit/MS17-010)
- Módulo Metasploit `ms17_010_eternalblue`: arquitetura x64; autenticação padrão é anônima; permite SMBUser/SMBPass/SMBDomain — [Rapid7 DB](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)
- zerosum0x0/RiskSense reportam que o código vulnerável existe no Windows 10 1511 e que o exploit foi portado para Windows 10 — [zerosum0x0, 07/06/2017](https://zerosum0x0.blogspot.com/2017/06/eternalblue-exploit-analysis-and-port.html)
- Discrepância: o infobox da Wikipedia lista também Windows 95/98/Me/NT 3.x/NT 4.0/2000 como afetados — [Wikipedia, EternalBlue](https://en.wikipedia.org/wiki/EternalBlue). Não encontrei respaldo em fonte primária (o boletim lista apenas Vista em diante, e o NVD também só cita Vista SP2 em diante). Tratar como não confirmado/provavelmente incorreto para o EternalBlue específico.

### Inferências
- A janela "Windows < 8 vulnerável ao exploit original; Windows 8+ vulnerável à falha mas com exploração mais difícil/exigindo adaptação" é uma síntese do pesquisador sobre Check Point, Worawit e boletim.
- Windows XP/Server 2003: o boletim os omite por estarem fora do ciclo de vida, mas a Microsoft publicou patch em maio/2017; não consegui verificar em fonte primária se o bug exato do CVE-2017-0144 se manifesta idêntico nessas versões (o recorte "XP afetado" vem de fontes secundárias e do patch de emergência).

### Gaps
- Não encontrei tabela oficial definitiva "Windows XP/2003 afetado por CVE-2017-0144 especificamente"; o patch de emergência (KB4012598) cobre o conjunto MS17-010.
- Não verifiquei quais builds do Windows 10 posteriores (1703+) estão imunes; sabe-se que 1607 recebeu o KB4013429 e que 1709+ não instala SMBv1 por padrão (exceto Home/Pro).

---

## 5. Exploits relacionados do Equation Group (EternalRomance, EternalChampion, EternalSynergy) e diferenças em relação ao EternalBlue

### Takeaway
Microsoft confirma que EternalBlue, EternalChampion, EternalRomance e EternalSynergy foram todos "Addressed by MS17-010", mas não publicou um mapeamento exploit-por-CVE. O mapeamento comumente citado (EternalRomance = CVE-2017-0145, EternalSynergy = CVE-2017-0143, EternalChampion = CVE-2017-0146 com 0143/0147 envolvidos) não foi confirmado integralmente por fonte primária; o módulo Metasploit psexec cita CVE-2017-0143, 0146 e 0147 para os três, e o 0145 não aparece ali. Tecnicamente, EternalRomance/Synergy/Champion exigem named pipe (acesso a share), enquanto o EternalBlue exige apenas IPC$.

### Cited Findings
- MSRC (abril/2017), tabela dos exploits vazados: EternalBlue, EternalChampion, EternalRomance e EternalSynergy = "Addressed by MS17-010"; os outros (EmeraldThread/MS10-061, EsikmoRoll/MS14-068, EducatedScholar/MS09-050, EclipsedWing/MS08-067, ErraticGopher/CVE-2017-8461; EnglishmanDentist/CVE-2017-8487; EsteemAudit/CVE-2017-0176; ExplodingCan/CVE-2017-7269) são tratados separadamente. Sem CVEs na tabela para os quatro "Eternal*" — [Microsoft MSRC, "Protecting customers and evaluating risk"](https://www.microsoft.com/en-us/msrc/blog/2017/04/protecting-customers-and-evaluating-risk)
- Módulo Metasploit `ms17_010_psexec` implementa EternalRomance, EternalSynergy e EternalChampion; CVEs listados: CVE-2017-0143, CVE-2017-0146, CVE-2017-0147. Descreve a cadeia como obtendo write-what-where, sobrescrevendo informações de sessão com uma sessão de Administrator, explorando "type confusion between Transaction and WriteAndX requests and a race condition in Transaction requests"; "more reliable than the EternalBlue exploit, but requires a named pipe" — [Rapid7 DB, ms17_010_psexec](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_psexec/)
- Worawit (tabela de diferenças): EternalBlue = IPC$ only, Windows < 8, risco maior de crash. EternalChampion = named pipe, "No chance of crashing the target"; estágios: leak, controle de RIP, execução de código. EternalRomance = named pipe, Windows < 8 (o info-leak foi corrigido no Windows 8), estágios: leak, out-of-bounds write, controle de transação para arbitrary read/write. EternalSynergy = named pipe, Windows 8+ (autor crê ser adaptação do EternalRomance), usa outro info-leak e heap spraying com large paged pool — [GitHub worawit/MS17-010](https://github.com/worawit/MS17-010)
- Wikipedia (terciária): EternalRomance e EternalChampion foram portados por Sean Dillon em fevereiro/2018 para todas as versões do Windows desde 2000 e liberados como módulos Metasploit; a página não mapeia CVEs para eles — [Wikipedia, EternalBlue](https://en.wikipedia.org/wiki/EternalBlue)
- Na NVD, 0143, 0144, 0145, 0146 e 0148 são descritos como "different from" os demais (cinco bugs RCE distintos); 0147 é info leak — [NVD CVE-2017-0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143)
- O Metasploit EternalBlue cita todos os seis CVEs (0143-0148), o que reflete que o módulo foi referenciado ao boletim inteiro, não que o exploit use os seis bugs — [Rapid7 DB, ms17_010_eternalblue](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)

### Inferências
- Os mapeamentos "EternalRomance = 0145" e "EternalSynergy = 0143" (frequentes em wikis e posts) NÃO foram confirmados por nenhuma fonte primária que li; o módulo psexec do Rapid7 aponta 0143/0146/0147 para o trio. Recomendação: no trabalho, apresentar como "mapeamento reportado por fontes secundárias" e citar o MSRC apenas para "corrigidos por MS17-010".
- CVE-2017-0147 aparece associado ao info leak usado nos exploits baseados em named pipe (Rapid7 psexec; Worawit descreve um estágio "leak"). A relação "0147 = estágio de leak" é inferência combinando esses dois, não afirmação literal.
- CVE-2017-0148 (CVSS v3.1 8.1, AC:H) é o único cujo NVD marca complexidade alta e CWE-20 explícito; fontes lidas não o associam a nenhum exploit nomeado.

### Gaps
- Mapeamento oficial e verificável de cada Eternal* para CVE específico não encontrado em fonte primária. Sugestão: consultar Malpedia, Trend Micro/Kaspersky ou o BUG.txt do Worawit, que lista os nove bugs, para cruzar com os seis CVEs.
- A afirmação de um resultado de busca de que "MSRC aponta CVE-2017-0146 e 0147 como solução para EternalChampion" não foi verificada; a tabela do MSRC que li não traz CVEs.

---

## 6. Classificação CISA KEV, datas e uso em ransomware

### Takeaway
Os seis CVEs estão no catálogo CISA KEV, adicionados entre 03/11/2021 e 24/05/2022 (CVE-2017-0143 foi o primeiro, em 03/11/2021, no lançamento inicial do catálogo; CVE-2017-0144 e -0145 em 10/02/2022). Todos têm `knownRansomwareCampaignUse = Known`.

### Cited Findings
- Dados do KEV (catálogo versão 2026.11.13, lido de [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json); catálogo web: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)):

  | CVE | Nome KEV | Data adicionada | Prazo (dueDate) | Ransomware | CWE (KEV) |
  |---|---|---|---|---|---|
  | CVE-2017-0143 | Microsoft Windows Server Message Block (SMBv1) Remote Code Execution Vulnerability | 03/11/2021 | 03/05/2022 | Known | CWE-20 |
  | CVE-2017-0144 | Microsoft SMBv1 Remote Code Execution Vulnerability | 10/02/2022 | 10/08/2022 | Known | CWE-20 |
  | CVE-2017-0145 | Microsoft SMBv1 Remote Code Execution Vulnerability | 10/02/2022 | 10/08/2022 | Known | CWE-20 |
  | CVE-2017-0146 | Microsoft Windows SMB Remote Code Execution Vulnerability | 25/03/2022 | 15/04/2022 | Known | CWE-20 |
  | CVE-2017-0147 | Microsoft Windows SMBv1 Information Disclosure Vulnerability | 24/05/2022 | 14/06/2022 | Known | CWE-200 |
  | CVE-2017-0148 | Microsoft SMBv1 Server Remote Code Execution Vulnerability | 06/04/2022 | 27/04/2022 | Known | CWE-20 |

  (datas convertidas de ISO; ação exigida: "Apply updates per vendor instructions."; descrição KEV de 0144: "The SMBv1 server in multiple Microsoft Windows versions allows remote attackers to execute arbitrary code via crafted packets.")
- O NVD espelha os campos CISA (`cisaExploitAdd`/`cisaActionDue`) idênticos — [NVD API CVE-2017-0144](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0144)
- Contexto de uso: Wikipedia cita WannaCry (12/05/2017), NotPetya (27/06/2017), uso pelo grupo chinês Buckeye (APT3) desde março de 2016 e Retefe desde 05/09/2017; NSA teria conhecido a falha por mais de cinco anos; vazamento pelos Shadow Brokers em 14/04/2017; patch em 14/03/2017 — [Wikipedia, EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) (terciária; verificar nas fontes primárias antes de citar no trabalho)
- Diferença entre prazo e data: o prazo de CVE-2017-0144/0145 (10/08/2022) é maior que o de 0143, 0146, 0148 (prazos de ~2-6 meses), indicando que a CISA não aplicou prazo uniforme — [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

### Inferências
- A data do patch (03/2017) versus a inclusão no KEV (11/2021 a 05/2022) mostra que o KEV foi criado depois (catálogo inicial em novembro/2021 — inferência a partir da data do 0143 e do fato de ser a data mais antiga do conjunto; não confirmei a data de criação do KEV em fonte oficial).
- Para o trabalho: a classificação oficial é "exploração conhecida e uso em ransomware conhecido" para todos os seis, inclusive o info leak.

### Gaps
- Não verifiquei a data exata de lançamento do KEV (03/11/2021 é a data de lançamento amplamente citada, mas não foi checada em fonte primária nesta pesquisa).
- Descrição "Known" refere-se ao campo `knownRansomwareCampaignUse` do KEV; não identifiquei campanhas específicas por CVE.
- O uso pelo APT3/Buckeye (Symantec) e Retefe precisa de fonte primária (Symantec/Trend Micro) antes de ir para o relatório final.

---

## Resumo de discrepâncias e alertas para o grupo

- VU#867968 (CERT/CC) é CVE-2017-0016/MS17-012 (SMB2), não MS17-010 — [CERT/CC](https://www.kb.cert.org/vuls/id/867968).
- CWE: NVD (NVD-CWE-noinfo) vs. KEV (CWE-20) — [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) vs. [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- "Não autenticado" (Microsoft: "in most situations") vs. CVSS v3.1 PR:L (NVD) vs. Metasploit padrão anônimo — [Microsoft Learn](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0144), [Rapid7](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/).
- Versões afetadas: "Windows < 8" (Check Point/Worawit, sobre o exploit) vs. lista do boletim (Vista a Server 2016, incluindo 8.1/10) vs. Wikipedia (inclui Windows 9x/NT, sem respaldo).
- Mapeamento Eternal* para CVE: sem fonte primária; Rapid7 psexec cita 0143/0146/0147 (sem 0145) para Romance/Synergy/Champion.
- Boletim: a tabela de severidade lista 0143-0146 e 0148 como RCE e 0147 como Information Disclosure (Important); a segunda tabela de "Vulnerability Information" do boletim reproduz os seis.
