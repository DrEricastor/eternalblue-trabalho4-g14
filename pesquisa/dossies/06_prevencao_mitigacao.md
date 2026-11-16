# Prevenção, mitigação e remediação contra EternalBlue / MS17-010 e exploração de SMBv1 (dossiê, posição em novembro de 2026)

Nota ao redator: tudo abaixo foi lido em páginas primárias (Microsoft Learn, CISA, NAO, CTIR Gov, Nmap, Rapid7) salvo indicação. Itens que NÃO pude verificar estão em "Gaps". Duas correções ao enunciado original: (1) CERT/CC VU#867968 NÃO é o EternalBlue (ver Seção 5); (2) o KB4012598 tem pacotes distintos para Vista/2008 (patch normal de 14/03/2017) e para XP/2003/8 (emergencial de maio/2017), mas o mesmo número de KB (ver Seção 1).

---

## 1. Patching: MS17-010, KBs por SO, verificação e distribuição

### Takeaway
O boletim MS17-010 (Security Update for Microsoft Windows SMB Server, KB4013389) foi publicado em 14/03/2017 e corrige 6 CVEs (CVE-2017-0143, -0144, -0145, -0146, -0147, -0148); a Microsoft declarou que não havia "mitigating factors", só o workaround de desabilitar SMBv1. A correção segue como controle nº 1: o WannaCry (12/05/2017) atingiu máquinas que simplesmente não tinham o patch, e a Microsoft publicou em maio de 2017 o KB4012598 também para XP/2003/Windows 8, fora do suporte.

### Cited Findings
- Boletim MS17-010 publicado em 14/03/2017 ("Security Update for Microsoft Windows SMB Server (4013389)"), v1.0, classificado Critical para todas as versões suportadas; corrige o tratamento de requisições especialmente criadas pelo servidor SMBv1; "Microsoft has not identified any mitigating factors"; workaround único = desabilitar SMBv1 (KB 2696547, ou desmarcar "SMB1.0/CIFS File Sharing Support" no Painel de Controle / Server Manager) — [MS17-010 (Microsoft Learn)](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- CVEs cobertos: CVE-2017-0143, -0144, -0145, -0146, -0148 (RCE, Critical) e CVE-2017-0147 (divulgação de informação, Important) — [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Tabela de KBs (extraída diretamente do boletim):
  - Windows Vista SP2 (x86/x64) e Windows Server 2008 SP2 (x86/x64/Itanium, inclusive Server Core): **KB4012598** (substitui 3177186 de MS16-114) — [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
  - Windows 7 SP1 e Server 2008 R2 SP1 (inclusive Itanium e Server Core): **KB4012212** (Security Only) e **KB4012215** (Monthly Rollup; substitui 3212646) — [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
  - Windows 8.1 e Server 2012 R2 (inclusive Server Core): **KB4012213** (Security Only) e **KB4012216** (Monthly Rollup; substitui 3205401); Windows RT 8.1: KB4012216 (somente via Windows Update) — [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
  - Windows Server 2012 (não R2): **KB4012214** (Security Only) e **KB4012217** (Monthly Rollup; substitui 3205409) — [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
  - Windows 10 RTM (1507): **KB4012606**; Windows 10 1511: **KB4013198**; Windows 10 1607 e Server 2016 (inclusive Server Core): **KB4013429** (cumulativos) — [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Os pacotes Windows 7/8.1/Server 2012 existem em duas modalidades por causa da mudança de modelo de servicing de out/2016 (Security Only vs. Monthly Rollup) — [MS17-010, nota de rodapé 1](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Patch emergencial para plataformas fora de suporte: a Microsoft liberou o update para Windows XP, Windows 8 e Windows Server 2003 (somente custom support) em 13/05/2017; links de download para Server 2003 SP2 x86/x64, XP SP2 x64, XP SP3 x86, XP Embedded SP3 e Windows 8 x86/x64 — [MSRC, "Customer Guidance for WannaCrypt attacks" (13/05/2017)](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks)
- O KB desse patch é KB4012598: CISA/US-CERT aponta o link do Catálogo "KB4012598" para XP, 8 e Server 2003 — [CISA TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware); página de download do Microsoft Download Center "Security Update for Windows XP SP3 for XPe (KB4012598)" lista MS17-010 em "Security bulletins" — [Download Center id=55247](https://www.microsoft.com/en-us/download/details.aspx?id=55247)
- Microsoft Security Advisory 4025685 (13/06/2017, "Guidance for older platforms") lista KB4012598 para MS17-010 em XP SP3, XP x64 SP2, Server 2003 SP2 (x86/x64), Vista SP2 e Windows 8; também KB4012583 (MS17-013), KB958644 (MS08-067) etc.; reitera que não muda a política de suporte e urge migração — [Advisory 4025685](https://support.microsoft.com/en-gb/help/4025687/microsoft-security-advisory-4025685-guidance-for-older-platforms)
- Windows Defender recebeu detecção Ransom:Win32/WannaCrypt em 13/05/2017 e o MSRT foi atualizado em 22/05/2017; sistemas com Windows Update ligado já estavam protegidos desde março; Microsoft recomenda bloquear protocolos legados (SMBv1) na rede e linka guias de Intune, SQL de ConfigMgr e OMS para relatar a conformidade com MS17-010 — [MSRC (13/05/2017)](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks)
- Verificação de patch com Get-HotFix: o cmdlet usa a classe WMI Win32_QuickFixEngineering; aceita `-Id` e `-ComputerName`; exemplo oficial lista computadores sem um KB específico (`if (!(Get-HotFix -Id KB957095 -ComputerName $_)) {...}`); limitação documentada: só retorna atualizações do CBS, não as instaladas via MSI/Windows Update site — [Get-HotFix (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix)
- Verificação remota por rede (não autenticada): script Nmap `smb-vuln-ms17-010` (categorias vuln, safe; autor Paulino Calderon) — conecta ao `IPC$`, faz transação em FID 0 e procura `STATUS_INSUFF_SERVER_RESOURCES` (indica host sem patch); uso: `nmap -p445 --script smb-vuln-ms17-010 <alvo>` ou `nmap -p445 --script vuln <alvo>`; saída exemplo "VULNERABLE, CVE-2017-0143" — [Nmap NSE doc](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html); script companheiro `smb-double-pulsar-backdoor` (mesma página, "See also")
- Metasploit: módulo auxiliar de detecção `auxiliary/scanner/smb/smb_ms17_010`; usa divulgação de informação para saber se o patch está aplicado, não exige credenciais válidas (logon nulo em IPC$), e, em hosts sem patch, procura infecção por DoublePulsar — [Rapid7 DB](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010/) (a página não afirma literalmente "nunca explora", mas o módulo é auxiliar/scanner, sem payload)
- Distribuição: para o ambiente corporativo a Microsoft indicou Windows Update/Intune/ConfigMgr/OMS; NIST SP 800-40 Rev. 4 (abril/2022) trata patching como "preventive maintenance" e orienta estratégia corporativa (descobrir, priorizar, obter, implantar, confirmar) — [MSRC](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks); [NIST SP 800-40r4](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
- CVE-2017-0144 consta no catálogo KEV da CISA (adicionado 10/02/2022, prazo 10/08/2022, uso em ransomware "Known") — conforme espelhos terceiros do KEV, não a página da CISA: [CIRCL KEV](https://vulnerability.circl.lu/known-exploited-vulnerabilities-catalog/27723d1b-b435-4e44-909f-004191f29310), [cvefeed](https://cvefeed.io/vuln/detail/CVE-2017-0144)
- Fim de suporte: Windows 7 e Server 2008/2008 R2 terminaram em 14/01/2020; ESU do Windows 7 acabou em 10/01/2023; Server 2008 R2 ESU Year 4 só para VMs no Azure até 09/01/2024 — [Windows 7 EOS FAQ (Microsoft Learn)](https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-7-eos-faq/windows-7-end-support-faq-general), [KB 4527875](https://support.microsoft.com/help/4527875) (conteúdo conforme resumo de busca; datas do ESU de embedded são conflitantes entre fontes, ver Gaps)
- Windows 10 chegou ao fim de suporte em 14/10/2025 (ESU para quem contratou) — [Windows LAPS overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)

### Inferences
- Para apresentar: KB "certo" depende do modelo de servicing; em Windows 7/8.1 o Rollup (KB4012215/4012216) é o mais seguro operacionalmente, e o Security-Only (KB4012212/4012213) exige instalar o rollup mensal subsequente por conta própria.
- O Windows 10 1703 (Creators Update, abril/2017) não aparece na tabela do boletim; a inferência é que já saiu com o código corrigido, mas isso não está dito na página lida.
- Em novembro/2026, todo sistema que ainda dependa apenas de KB4012xxx está em plataforma sem suporte (Win 7/2008 R2/8.1 e Server 2012/2012 R2 também já em fim de ciclo, ver Gaps); patch de 2017 é condição necessária, não suficiente.

### Gaps
- Página de suporte KB4013389 (support.microsoft.com) retornou 404 no WebFetch; citei o boletim em vez disso. Os links de KB individuais (KB4012212 etc.) não foram abertos um a um; foram verificados apenas pela tabela do boletim.
- Comando `wmic qfe list | findstr KB4012212` e scripts "Microsoft scripts" para varredura MS17-010 (ConfigMgr SQL queries): a existência é citada pelo MSRC, mas o conteúdo não foi lido. `wmic qfe` não foi verificado em fonte e o WMIC está obsoleto no Windows 11; não consegui confirmar documentação oficial atualizada.
- O pacote KB4012598 para Windows 8 e Server 2003 está listado pelo Catálogo, mas as datas de publicação divergem entre fontes (maio/2017 vs. 15/07/2024 no Download Center para XPe, que é provavelmente republicação). Confirmar data exata antes de afirmar "13/05/2017" para cada pacote; a data 13/05/2017 vem do post do MSRC.
- Datas de fim de suporte de Server 2012/2012 R2/8.1 não foram pesquisadas.
- Página CISA do KEV não foi lida diretamente (somente espelhos).

---

## 2. Desabilitar/remover SMBv1 (Microsoft), padrões do Windows 10/11/Server e mudanças 2024–2026

### Takeaway
Microsoft recomenda desinstalar SMBv1 (cliente e servidor) em vez de apenas desativar; desde o Windows 10 1709 e Server 2019 ele não vem instalado por padrão, e o Windows 11 não o contém em instalação limpa. Em 2024–2026 a Microsoft foi além: SMB signing obrigatório por padrão no Windows 11 24H2/Server 2025, remoção do NTLMv1 e roteiro de NTLM desabilitado por padrão.

### Cited Findings
- Comandos oficiais (Microsoft Learn, atualizado em 08/09/2026):
  - Detectar/Desabilitar/Habilitar recurso (reinicia): `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` / `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` / `Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
  - Servidor SMB (sem reinício): `Get-SmbServerConfiguration | Select EnableSMB1Protocol`; `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
  - Windows 7/2008 R2/Vista/2008: registro `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, valor `SMB1` REG_DWORD = 0 (padrão 1; exige reinício); PowerShell: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force`
  - Cliente SMBv1 (todas as versões): `sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi` e `sc.exe config mrxsmb10 start= disabled` (ou GPP: `HKLM\SYSTEM\CurrentControlSet\services\mrxsmb10\Start`=4 e `LanmanWorkstation\DependOnService` = Bowser, MRxSmb20, NSI)
  - Servidor via GPO: Group Policy Preferences > Registry, `SMB1`=0 em LanmanServer\Parameters; aplicar em estações, servidores e DCs
  - Server Manager: Remove Roles and Features, desmarcar "SMB 1.0/CIFS File Sharing Support"; Stop using SMB1 cita também `Remove-WindowsFeature FS-SMB1`
  - Fonte: [Detect, enable, and disable SMBv1, SMBv2, SMBv3 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3); [Stop using SMB1 (Ned Pyle, 16/09/2016)](https://techcommunity.microsoft.com/blog/filecab/stop-using-smb1/425858)
- Auditoria de uso de SMBv1: `Set-SmbServerConfiguration -AuditSmb1Access $true`; consultar `Get-SmbServerConfiguration | Select AuditSmb1Access`; eventos ID 3000 em `Microsoft-Windows-SMBServer\Audit`; em Windows 7/2008 R2 via registro `AuditSmb1Access` DWORD=1 (backport) — [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3); [Stop using SMB1](https://techcommunity.microsoft.com/blog/filecab/stop-using-smb1/425858)
- No cliente, eventos `Microsoft-Windows-SmbClient/Security` ID 32002 (negociação SMB1 recebida) e 32000 (SMB1 recebido mas não negociável) mostram quem exige SMB1 — [SMBv1 Not Installed by Default (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
- Argumentos de Ned Pyle: SMB1 perde pre-authentication integrity, secure dialect negotiation, criptografia, bloqueio de guest inseguro e signing mais forte; um man-in-the-middle pode forçar downgrade para SMB1 a menos que o share exija criptografia; usos legítimos remanescentes: XP/2003 sob custom support, softwares antigos de gerenciamento que usam browsing, multifuncionais antigas "scan to share"; recomenda mapear drives/impressoras em vez de depender de browsing e pedir SMB2+ aos fornecedores (lista "SMB1 Product Clearinghouse", aka.ms/stillneedssmb1) — [Stop using SMB1](https://techcommunity.microsoft.com/blog/filecab/stop-using-smb1/425858)
- Estado padrão: desde Windows 10 1709 / Windows Server 1709 o SMBv1 não é instalado por padrão; Win 10 Enterprise/Education/Pro for Workstations e Server 2019+ sem cliente nem servidor em instalação limpa; Win 10 Home/Pro sem servidor; Win 10 Home/Pro 1709 mantêm cliente (auto-desinstala após 15 dias sem uso; a partir do 1809 o Pro não tem mais o cliente); "Windows 11 doesn't contain the SMBv1 server or client by default after a clean installation"; upgrades in-place de Enterprise/Education não removem automaticamente; reinstalação continua possível em todas as edições do Windows 10 e Server 2016; VMs do Azure Marketplace da Microsoft não têm binários SMB1; Microsoft deprecou publicamente o SMBv1 em 2014; sem SMB1, o Computer Browser/Network Neighborhood deixa de funcionar — [SMBv1 Not Installed by Default (atualizado 16/02/2026)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
- Alternativa para aplicações legadas: `New-SmbShare/Set-SmbShare -LeasingMode None` (somente em shares exigidos pelo fornecedor, nunca em dados de usuário ou shares de Scale-Out File Server) e Function Discovery (WS-Discovery) para substituir browsing — [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
- Windows 11 24H2 / Server 2025: assinatura SMB (signing) obrigatória para todas as conexões de saída e entrada por padrão (antes, apenas SYSVOL/NETLOGON e clientes de DCs); guest fallback desativado — [SMB security hardening (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening). Detalhe/conflito: a página de signing diz que o Windows 11 24H2 Enterprise/Pro/Education exige entrada e saída, o Server 2025 exige somente saída, e o 24H2 Home não exige nenhum — [Control SMB signing behavior](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing). A própria Microsoft diz para não desabilitar versões de SMB ou signing como contorno e sim habilitar signing no servidor remoto ou substituir o dispositivo — [Detect, enable, disable](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- Outros recursos 24H2/Server 2025: SMB authentication rate limiter (2 s de atraso por falha NTLM/Local KDC), bloqueio de NTLM no cliente SMB com exceções, controle de dialetos mínimo/máximo (`manage-smb-dialects`), mandato de criptografia no cliente, SMB over QUIC em todas as edições do Server 2025 (UDP 443, TLS 1.3) com controle de acesso por allowlist de clientes, Remote Mailslots desabilitados por padrão, regras de firewall internas sem portas NetBIOS 137–139 — [SMB security hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening); [Secure SMB traffic](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic)
- Verificar signing: `Get-SmbClientConfiguration | FL RequireSecuritySignature` e `Get-SmbServerConfiguration | FL RequireSecuritySignature`; habilitar: `Set-SmbClientConfiguration -RequireSecuritySignature $true` / `Set-SmbServerConfiguration -RequireSecuritySignature $true`; GPO "Microsoft network client: Digitally sign communications (always)"; recomendações: usar Kerberos em vez de NTLMv2, não conectar por IP, não usar CNAME — [Control SMB signing behavior](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- NTLM: roteiro oficial publicado em 29/01/2026 (atualizado 22/10/2026): Fase 1 auditoria aprimorada de NTLM (já disponível em Server 2025 e Win 11 24H2+); Fase 2 (2º semestre de 2026) IAKerb e Local KDC (pré-lançamento) e componentes do Windows preferindo Kerberos; Fase 3 NTLM de rede desabilitado por padrão na próxima versão major do Windows Server e clientes correspondentes, sem data; "does not mean completely removing NTLM yet" — [Advancing Windows security: disabling NTLM by default](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-security-disabling-ntlm-by-default/4489526)
- NTLMv1 removido do Windows 11 24H2 e Server 2025 (auditoria em modo audit a partir de setembro/2025 segundo a Microsoft) — [KB 5066470](https://support.microsoft.com/help/5066470) (conforme resultado de busca; página não aberta)

### Inferences
- A cadeia de defesa Microsoft para SMB hoje é: remover SMB1, exigir signing/encryption/dialeto mínimo 3.1.1, bloquear NTLM, limitar tentativas. Isso quebra a classe de ataque do EternalBlue (que não existe em SMB2/3), mas ataques de relay/credencial continuam relevantes.
- Impacto de compatibilidade: impressoras/scanners multifuncionais, NAS antigos, dispositivos industriais/médicos e Samba antigo; a Microsoft diz que normalmente "aren't likely running Windows" — [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows).
- Desabilitar SMBv1 em DCs exige cuidado se houver sistemas Windows legados/Linux/parceiros que acessem SYSVOL só com SMB1 — o aviso consta na página de GPO.

### Gaps
- KB2696547 (página original em support.microsoft.com) não foi aberta; a Microsoft Learn atual substitui o conteúdo e o boletim MS17-010 ainda aponta para o KB.
- Não consegui confirmar fonte primária de uma mudança de 2024–2026 que remova os binários do SMB1 do Windows 11 (apenas "não instalado por padrão em instalação limpa"). Busca não retornou nada confirmado.
- KB 5066470 (NTLMv1) só visto em snippet de busca.
- Inconsistência a flagar no relatório: página de signing diz "latest Insider Preview builds" em um trecho antigo e depois cita Windows 11 24H2 estável; o texto de comparação por edição (Pro/Enterprise/Education sim, Home não, Server 2025 só saída) vem da própria página de signing, enquanto a página de hardening resume "todas as conexões". Citar a página de signing para detalhe.

---

## 3. Controles de rede: bloquear 445/139 e UDP 137/138, segmentação, não expor SMB, VPN/zero trust

### Takeaway
Todas as autoridades pesquisadas (Microsoft, CISA, CTIR Gov, NCSC) convergem: bloquear TCP 445 (e 139, UDP 137/138) no perímetro nos dois sentidos, usar firewall de host contra movimento lateral e segmentar/isolar plataformas obsoletas. A NAO concluiu que a gestão de firewalls voltados à internet teria protegido as organizações do NHS mesmo sem patch.

### Cited Findings
- Microsoft: bloquear TCP 445 inbound da internet no firewall corporativo; bloquear TCP 445 outbound para a internet (exceto cenários de nuvem como Azure Files/Office 365, preferencialmente via VPN ou SMB over QUIC em UDP 443 com TLS 1.3) — [Secure SMB Traffic](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic)
- Microsoft: inventariar uso de SMB (auditoria de evento 5140 / File Share; `Get-FileShareInfo` do AZSBTools), usar Windows Defender Firewall com regras inbound/outbound e Connection Security Rule (Isolation, Kerberos) e, onde não necessário, parar/desabilitar os serviços Server e Workstation (nunca no Server service de DCs/servidores de arquivos nem no Workstation de membros AD) — [Secure SMB Traffic](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic)
- Portas e templates: TCP 445 (SMB), UDP 137/138 e TCP 139 (NetBIOS); no host, desabilitar as regras embutidas "File and Printer Sharing (SMB-In)", "Netlogon (NP-In)", "Remote Event Log Management (NP-In)", "Remote Service Management (NP-In)", bloquear TCP 445 inbound em máquinas que não hospedam shares (não em DCs/servidores de arquivos), bloquear TCP 445 outbound em perfis Guest/Public e, em Domain/Private, permitir apenas para IPs de DCs/servidores de arquivos — [Preventing SMB traffic from lateral connections and entering or leaving the network](https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network-c0541db7-2244-0dce-18fd-14a3ddeb282a)
- CISA TA17-132A (12/05/2017): se não for possível aplicar o patch, desabilitar SMBv1 e bloquear todas as versões de SMB na borda (TCP 445, UDP 137-138, TCP 139), ponderando a interrupção; ver também TA16-250A (segmentação, limitar comunicação lateral); o WannaCry varre faixas locais em UDP 137/138 e TCP 139/445; domínio kill switch (`iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com`): a CISA recomenda NÃO bloqueá-lo — [CISA TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)
- CISA TA17-181A (Petya/NotPetya): desabilitar SMBv1 e bloquear SMB na borda; proteger WMI, limitar WMI remoto e compartilhamento de arquivos, bloquear execução remota via PsExec, firewalls de host bloqueando comunicação estação-a-estação, segregar redes e funções, gerenciamento fora de banda — [CISA TA17-181A](https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware)
- CTIR Gov (Brasil) Alerta nº 02/2017 (12/05/2017): aplicar o patch MS17-010, isolar redes infectadas, bloquear UDP 137/138 e TCP 139/445 até resolver o problema, manter backups, não pagar resgate, revisar privilégios administrativos, monitorar tráfego anômalo — [CTIR Gov via CODATA-PB](https://codata.pb.gov.br/noticias/ctir-gov-alerta-no-02-2017-2013-ataques-de-ransomware-wncry-atraves-de-vulnerabilidade-no-windows); o Alerta nº 04/2017 (Petya/Petrwrap) repete as orientações — [CTIR Gov Alerta 04/2017 (PDF)](https://www.gov.br/ctir/pt-br/centrais-de-conteudo/publicacoes/alertas/2017/alerta_2017_04_ransomwarepetrwrap.pdf) (conteúdo conforme resumo de busca)
- Canadá (Cyber Centre AL17-006) recomenda aplicar o patch e bloquear portas SMBv1 no perímetro nos dois sentidos — [Cyber Centre AL17-006](https://www.cyber.gc.ca/en/alerts-advisories/ransomware-wannacry) (conforme resumo de busca)
- NCSC UK: segregar plataformas obsoletas do restante da rede ("properly segregated"); firewalls configurados para negar conexões inbound por padrão; manter inventário de versões instaladas; usar MFA; remover permissões desnecessárias; impedir uso de contas privilegiadas para email e web; desabilitar RDP se não necessário; ver "Preventing lateral movement" e "Obsolete products" — [NCSC: Mitigating malware and ransomware attacks](https://www.ncsc.gov.uk/guidance/ransomware-latest-ncsc-guidance); [NCSC: WannaCry guidance updates (19/05/2017)](https://www.ncsc.gov.uk/blog-post/wannacry-ransomware-guidance-updates)
- NAO (27/10/2017): ao menos 81 de 236 trusts da Inglaterra foram afetados, mais 603 organizações de atenção primária (595 GPs); 6.912 consultas canceladas, estimativa de mais de 19.000; 5 A&E desviaram pacientes; todas as organizações infectadas tinham sistemas Windows sem patch ou sem suporte; "Managing internet-facing firewalls would have protected organisations whether or not they had patched"; NHS Digital emitiu alertas críticos em março e abril de 2017; em 2014 o governo mandou migrar de XP até abril/2015; antes de 12/05 o Departamento não tinha meio formal de checar a conformidade — [NAO](https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/)
- Segmentação de OT/ICS: NCCIC publicou um fact sheet de ICS sobre WannaCry — [CISA ICS FactSheet (PDF)](https://www.cisa.gov/uscert/sites/default/files/FactSheets/NCCIC%20ICS_FactSheet_WannaCry_Ransomware_S508C.pdf) (somente título visto em busca; conteúdo não lido)

### Inferences
- Defesa em camadas: perímetro (bloquear 445 in/out) não ajuda contra worm já dentro (WannaCry via phishing/portador, NotPetya via software M.E.Doc): segmentação interna e firewall de host bloqueando estação-estação são o controle que contém propagação lateral.
- VPN/zero trust: a Microsoft indica SMB over QUIC (UDP 443, TLS 1.3, allowlist de clientes) como alternativa ao SMB sobre internet; microssegmentação e zero trust não estão em página oficial lida de forma específica ao SMB, então a ligação é inferência.
- Observação operacional: não bloquear o domínio kill switch durante análise (CISA).

### Gaps
- Não encontrei documento CERT.br específico sobre WannaCry (a busca devolveu apenas CTIR Gov e as cartilhas de ransomware do CERT.br: [CERT.br — Responder a ransomware](https://cert.br/docs/ransomware/en/respond/), [CERT.br — detectar](https://www.cartilha.cert.br/docs/ransomware/en/detect/), conteúdo apenas resumido em busca). Sugiro tratar o CTIR Gov como a fonte brasileira primária; a linha do tempo do CERT.br (MS17-010 em 14/03/2017; propagação em 12/05/2017) veio de snippet e não foi aberta.
- Sem fonte primária lida para "zero trust"/microsegmentação contra SMB; sem conteúdo do CISA ICS fact sheet.

---

## 4. Detecção/resposta: IDS/IPS, EDR/AV, scanning, inventário, signing, privilégio mínimo, higiene de credenciais, backups, isolamento de legado, virtual patching

### Takeaway
Detecção por rede (assinaturas EternalBlue/DoublePulsar) e por endpoint (AV/EDR, ATP) quebra a fase de exploração e de movimento lateral; mas o NotPetya mostrou que patching apenas de SMB não basta porque combinou EternalBlue/EternalRomance com Mimikatz, PsExec e WMIC; daí a importância de Credential Guard, LAPS e privilégio mínimo.

### Cited Findings
- NotPetya (TA17-181A): movimento lateral por (1) credenciais roubadas com Mimikatz modificado + WMIC/PsExec (método "first and usually most effective"), (2) EternalBlue em hosts com SMBv1 sem patch, (3) EternalRomance; entrega via atualização comprometida do M.E.Doc (backdoor desde 14/04/2017, evento de 27/06/2017); criptografia AES e alteração do MBR; chave de criptografia não ligada ao ID da vítima, recuperação improvável mesmo pagando; atribuição do governo dos EUA à Rússia em 15/02/2018 — [CISA TA17-181A](https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware)
- Microsoft sobre Petya: o worm copia a si mesmo para `admin$` remotos e executa com PsExec/WMIC, enumera sub-redes DHCP em DCs/servidores, usa EternalBlue (CVE-2017-0144) e EternalRomance (CVE-2017-0145); mitigações citadas: MS17-010, desabilitar SMBv1 (KB 2696547), bloquear TCP 139/445 no roteador/firewall, desabilitar temporariamente WMI remoto e compartilhamento de arquivos, Credential Guard, Device Guard, Windows Defender ATP (detecta comportamento sem atualização de assinatura, como PsExec renomeado e criação de `perfc.dat`), Windows Defender Antivirus (Ransom:Win32/Petya a partir da definição 1.247.197.0), Windows 10 Creators Update — [Microsoft Security blog, 27/06/2017](https://www.microsoft.com/security/blog/2017/06/27/new-ransomware-old-techniques-petya-adds-worm-capabilities/)
- Credential Guard: usa VBS para isolar hashes NTLM, TGTs Kerberos e credenciais armazenadas, bloqueando pass-the-hash e pass-the-ticket; habilitado por padrão no Windows 11 22H2 e Server 2025 em sistemas ingressados no domínio (exceto DCs) que atendam aos requisitos, sem UEFI lock; edições Enterprise/Education (Pro não licenciado); não protege o banco do AD nem o SAM; quebra aplicações que exigem NTLMv1, DES, delegação irrestrita — [Credential Guard overview (atualizado 2026)](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- Windows LAPS: gerencia/rotaciona a senha do administrador local (e DSRM) e a guarda no AD ou Entra ID; "Protection against pass-the-hash and lateral-traversal attacks"; disponível sem custo no Windows 11 23H2+, e em Windows 10/11/Server 2019/2022 com a atualização de 11/04/2023; LAPS legado descontinuado a partir do Windows 11 23H2 — [Windows LAPS overview (atualizado 12/10/2026)](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- Assinatura SMB e relay: signing protege contra tampering/relay/spoofing e adversary-in-the-middle; hoje obrigatório por padrão no 24H2/Server 2025 (ver Seção 2) — [Control SMB signing behavior](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- IDS/IPS: o script Nmap e o módulo Metasploit descrevem a assinatura de rede do sondeio (transação em IPC$/FID 0 com STATUS_INSUFF_SERVER_RESOURCES); o script `smb-double-pulsar-backdoor` e o módulo Metasploit também detectam DoublePulsar — [Nmap NSE](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html), [Rapid7](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010/). Existem assinaturas comerciais para MS17-010: Trend Micro DDI "MS17-010 - Remote Code Execution - SMB (Request)" ([Trend Micro DDI rule 2528](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/network/ddi-rule-2528), conforme resultado de busca) e FortiGuard IPS "SMB1 Trans2 Secondary Handling Code Execution" ([FortiGuard IPS 43796](https://fortiguard.com/encyclopedia/ips/43796), conforme resultado de busca); trabalho acadêmico GIAC GREM descreve regras Snort anti-exploit para WannaCry — [GIAC GREM](https://www.giac.org/paper/grem/5549/reverse-engineering-wannacry-worm-anti-exploit-snort-rules/165237) (resultado de busca)
- CISA TA17-132A/181A (controles gerais): filtros anti-spam com SPF/DMARC/DKIM, escaneamento de email, AV com varredura regular, privilégios mínimos para contas e shares, desabilitar macros, treinamento, pen test anual, testar backups, manter backups separados e inacessíveis da rede local, plano de resposta a incidentes e continuidade, reportar a autoridades — [TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware); [TA17-181A](https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware)
- NCSC: backups offline e testados, escanear backups antes de restaurar, plano de IR exercitado; NCSC não recomendou foco em phishing para WannaCry por não ter visto evidência de propagação por phishing — [NCSC ransomware guidance](https://www.ncsc.gov.uk/guidance/ransomware-latest-ncsc-guidance); [NCSC blog, 19/05/2017](https://www.ncsc.gov.uk/blog-post/wannacry-ransomware-guidance-updates)
- Plataformas fora de suporte: Microsoft liberou o patch fora do ciclo mas reafirma que não muda a política e que clientes devem migrar — [Advisory 4025685](https://support.microsoft.com/en-gb/help/4025687/microsoft-security-advisory-4025685-guidance-for-older-platforms); NCSC manda segregar obsoletos — [NCSC](https://www.ncsc.gov.uk/guidance/ransomware-latest-ncsc-guidance)
- Rastreamento de ativos: NCSC recomenda saber quais versões de software estão instaladas para direcionar updates; Microsoft recomenda inventário de SMB e shares — [NCSC](https://www.ncsc.gov.uk/guidance/ransomware-latest-ncsc-guidance); [Secure SMB Traffic](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic)
- Resposta a incidentes: isolar redes infectadas e desconectar máquinas ao primeiro sinal (CTIR Gov); restaurar de backup limpo (CISA); pagar o resgate não garante recuperação — [CTIR Gov](https://codata.pb.gov.br/noticias/ctir-gov-alerta-no-02-2017-2013-ataques-de-ransomware-wncry-atraves-de-vulnerabilidade-no-windows); [TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)
- Brad Smith (Microsoft, 14/05/2017): segurança é responsabilidade compartilhada, manter sistemas atualizados é dever básico; criticou a estocagem de vulnerabilidades por governos e reiterou a proposta de uma "Digital Geneva Convention"; notou que muitos computadores continuavam sem patch cerca de dois meses depois de 14/03 — [Microsoft On the Issues](https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/)

### Inferences
- "Virtual patching" = IPS com assinatura MS17-010 na frente do host que não pode ser corrigido (legado, OT, médico), em combinação com ACL/VLAN; fontes lidas citam assinaturas de fornecedores (Trend Micro, Fortinet), mas não usam o termo "virtual patching" literalmente.
- Contra o NotPetya, os controles com maior efeito estão fora do patch: LAPS (senha local única), Credential Guard, restrição de PsExec/WMI e de admin$, segmentação. Em 2026 Credential Guard já vem habilitado por padrão em Windows 11 22H2+ domain-joined elegíveis, reduzindo custo de adoção.
- 3-2-1 offline: CISA/NCSC/CTIR Gov recomendam backups testados, separados da rede e offline, mas a regra "3-2-1" literal não aparece nas fontes lidas; é convenção de mercado.

### Gaps
- SIDs exatos de Snort/Suricata (ET Open/ET Pro, ex.: "ETERNALBLUE"/"DOUBLEPULSAR") não verificados: a busca não retornou um SID confiável; não inventei números. Sugere-se consultar o ruleset Emerging Threats/Snort Community diretamente.
- Sem fonte primária lida de Kaspersky, Trend Micro (além do nome da regra), Check Point, Cloudflare, Imperva nem SANS para este tema (por limite de orçamento de busca).
- CIS Controls (v8) e NIST SP 800-53 (SI-2 Flaw Remediation, CM-7, SC-7) não foram abertos; mapeamento é inferência a validar.

---

## 5. Documentos oficiais de orientação (CISA/US-CERT, CERT/CC, NCSC, CERT.br/CTIR Gov, NIST, CIS, MSRC, Brad Smith)

### Takeaway
Fontes primárias confirmadas: CISA TA17-132A e TA17-181A, MS17-010, MSRC "Customer Guidance for WannaCrypt attacks", Microsoft Advisory 4025685, Brad Smith (14/05/2017), NCSC (blog + guia), NAO (relatório), CTIR Gov 02/2017 e 04/2017. Correção importante: CERT/CC VU#867968 não é o EternalBlue.

### Cited Findings
- CISA/US-CERT TA17-132A "Indicators Associated With WannaCry Ransomware": publicado em 12/05/2017; revisões em 14/05, 16/05, 18/05/2017 e 07/06/2018 (atribuição à Coreia do Norte); contém dropper (MD5 5bef35496fcbdbe841c82f4d1ab8b7c2, serviço `mssecsvc2.0`, `tasksche.exe /i`), YARA e IOCs; resgate de ~0,1781 BTC (~US$ 300) — [CISA](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)
- CISA/US-CERT TA17-181A "Petya Ransomware": publicado em 01/07/2017; revisões em 03/07, 07/07, 28/07/2017 e 15/02/2018 — [CISA](https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware)
- CERT/CC VU#867968 (conforme o enunciado): a nota real é "Microsoft Windows SMB Tree Connect Response denial of service", CVE-2017-0016 (corrigido em MS17-012), um DoS de cliente SMB2 (BSOD em mrxsmb20.sys) com CVSS base 7.8; solução: aplicar MS17-012 e bloquear SMB de saída (TCP 139/445, UDP 137/138) para a WAN; data pública 01/02/2017, revisada 17/03/2017. NÃO trata de MS17-010 — [CERT/CC VU#867968](https://www.kb.cert.org/vuls/id/867968)
- MSRC: post "Customer Guidance for WannaCrypt attacks" de Phillip Misner (13/05/2017; atualização de 22/05/2017 com MSRT): instalar MS17-010, manter antimalware atualizado, cautela com documentos de origem desconhecida, bloquear protocolos legados, SMBv1; Windows 10 não foi alvo do ataque naquele dia — [MSRC](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks)
- NCSC UK: blog de 19/05/2017 "WannaCry ransomware guidance updates" (guias para administradores corporativos e para usuários domésticos; guia de plataformas obsoletas ampliado) e guia atual "Mitigating malware and ransomware attacks" — [NCSC blog](https://www.ncsc.gov.uk/blog-post/wannacry-ransomware-guidance-updates), [NCSC guidance](https://www.ncsc.gov.uk/guidance/ransomware-latest-ncsc-guidance); guias relacionados: [Preventing lateral movement](https://www.ncsc.gov.uk/guidance/preventing-lateral-movement), [Obsolete products](https://www.ncsc.gov.uk/collection/device-security-guidance/managing-deployed-devices/obsolete-products), [Vulnerability management](https://www.ncsc.gov.uk/guidance/vulnerability-management) (links vistos como referências da página, não abertos)
- NIST SP 800-40 Rev. 4, "Guide to Enterprise Patch Management Planning: Preventive Maintenance for Technology" (abril/2022, Souppaya e Scarfone; substitui Rev. 3 de julho/2013) — [NIST CSRC](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
- NAO, "Investigation: WannaCry cyber attack and the NHS" (27/10/2017) — [NAO](https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/)
- Brad Smith: "The need for urgent collective action to keep people safe online: Lessons from last week's cyberattack" (14/05/2017) — [Microsoft On the Issues](https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/)
- Brasil: CTIR Gov Alerta 02/2017 (WannaCry, 12/05/2017) e Alerta 04/2017 (Petya) — ver Seção 3.

### Inferences
- O enunciado cita "CERT/CC VU#867968" para o EternalBlue; deve ser corrigido no trabalho (o certo para MS17-010 é o boletim MS17-010 / CVE-2017-0144; não encontrei uma nota CERT/CC dedicada).
- "Microsoft Security Advisory 2696547" no enunciado é na verdade o KB 2696547 (artigo de suporte "How to enable and disable SMBv1, SMBv2, and SMBv3"), referenciado pelo MS17-010 como workaround; o "Security Advisory" correto sobre plataformas antigas é o 4025685.

### Gaps
- Nota CERT.br específica sobre WannaCry não localizada; CIS Controls e NIST SP 800-53 não abertos; CISA KEV na página oficial não aberta.
- Páginas arquivadas de TechNet (technet.microsoft.com/library/security/ms17-010) migraram para Microsoft Learn; o link legado pode quebrar.

---

## 6. Avaliação de cada contramedida (fase quebrada, custo/esforço, limitações) e por que muitas organizações falharam

### Takeaway
A tabela abaixo é síntese minha (Inferences) construída sobre os fatos citados nas seções 1–5; ela está marcada como inferência quando a fonte não diz literalmente o julgamento de custo/esforço.

### Cited Findings
- Causas de falha em organizações reais: alertas críticos do NHS Digital em março e abril/2017 não foram implementados; sem verificação formal de conformidade; sistemas XP/sem suporte apesar de orientação de 2014 para migrar até abril/2015; firewalls internet-facing mal geridos; falta de exercício de resposta a ataque cibernético nacional — [NAO](https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/)
- Dois meses depois do patch de 14/03, muitos computadores ainda estavam sem atualizar — [Brad Smith](https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/)
- Compatibilidade: desabilitar SMBv1 ou signing obrigatório pode impedir conexões com computadores de workgroup, shares com guest, servidores SMB de terceiros que não suportam signing; legado típico: impressoras/scanners, NAS antigos, softwares de gerenciamento que usam browsing — [Detect, enable, disable](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3); [Stop using SMB1](https://techcommunity.microsoft.com/blog/filecab/stop-using-smb1/425858); [Control SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- Bloquear SMB pode quebrar acesso a arquivos, dados ou dispositivos (aviso explícito) — [CISA TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)
- Credential Guard exige hardware/VBS, edição Enterprise/Education e pode quebrar NTLMv1/delegação irrestrita — [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)

### Inferences
Tabela de avaliação (síntese; "custo/esforço" é julgamento do autor, não de fonte):

| Contramedida | Fase quebrada | Custo/esforço (inferido) | Limitações principais |
|---|---|---|---|
| MS17-010 (KB4012xxx/4013xxx/4012598) | Prevenir (exploração) | Baixo-médio (WSUS/ConfigMgr/Intune; testes) | Exige SO suportado; legado/OT/médico sem janela de manutenção |
| Desinstalar/desabilitar SMBv1 (+AuditSmb1Access antes) | Prevenir (remove superfície) | Baixo no Windows; médio por inventário de dependentes | Quebra impressoras/NAS/scanners antigos, Samba antigo; DCs com clientes legados |
| Bloquear 445/139/137/138 no perímetro | Prevenir (entrada externa) e conter (saída) | Baixo | Não impede propagação interna; quebra acesso a nuvem se mal desenhado |
| Firewall de host + segmentação/VLANs/microssegmentação | Conter (movimento lateral) | Médio-alto | Exige mapa de fluxos; risco de quebra de apps |
| Remover SMB onde não usado (parar serviço Server/Workstation) | Prevenir/conter | Baixo | Nunca em DCs/file servers |
| SMB signing/encryption/dialeto mínimo | Prevenir (relay/tampering); não impede EternalBlue em SMB1 | Baixo no 24H2/Server 2025 (padrão) | Terceiros sem suporte; desativa guest |
| IDS/IPS com assinaturas MS17-010/DoublePulsar | Detectar (e bloquear em modo IPS) | Médio | Tráfego criptografado/segmentos não monitorados; assinaturas por fornecedor (SID não verificado) |
| AV/EDR (Defender, ATP) | Detectar/prevenir execução, lateralidade | Médio | Assinatura chegou depois do início do surto (13/05); depende de cobertura de agentes |
| Varredura de vulnerabilidades (Nmap NSE, Metasploit scanner, ConfigMgr, Get-HotFix) | Detectar exposição | Baixo | `Get-HotFix` só enxerga CBS; scanners podem gerar carga |
| Inventário de ativos | Pré-requisito de todos | Médio | Dispositivos OT/IoT não descobertos |
| LAPS, Credential Guard, privilégio mínimo, bloqueio de PsExec/WMI | Conter (pass-the-hash, NotPetya) | Médio | Credential Guard: hardware/edição; compatibilidade de apps |
| Backups 3-2-1/offline + testes de restauração | Recuperar | Médio | Não impede a infecção; backups online também são criptografados |
| Plano de IR e exercícios | Detectar/conter/recuperar | Médio | Exige treino; NAO apontou ausência de exercício e de responsáveis |
| Isolamento de legado (XP/2003/Win7 EOL), virtual patching | Conter | Médio-alto | É paliativo; migração é a solução |
| Migrar/aposentar OS sem suporte | Prevenir | Alto | Orçamento, certificação de dispositivos médicos/OT |

Por que muitas organizações falharam (síntese sustentada pelas fontes acima): atraso de patch (alertas ignorados, sem checagem de conformidade), sistemas sem suporte, firewalls mal geridos, legado dependente de SMBv1/Windows antigo, ausência de plano de resposta ensaiado; para OT/medical: impossibilidade de aplicar patch sem recertificação (inferência; só a NAO sobre NHS foi lida, não FDA/IEC).

### Gaps
- Nenhuma fonte primária lida sobre dispositivos médicos/OT especificamente (FDA, IEC 62443); o item OT/medical é inferência. O fact sheet CISA ICS não foi lido.
- Custos monetários dos controles não foram pesquisados.

---

## 7. Lições aprendidas (WannaCry/NotPetya) e tabela de defesa em profundidade

### Takeaway
WannaCry mostrou o custo de não corrigir uma vulnerabilidade com patch disponível há 8 semanas; NotPetya mostrou que patch e SMB sozinhos não bastam quando credenciais e administração remota viabilizam movimento lateral, e que a cadeia de suprimentos pode ser o vetor.

### Cited Findings
- Cronologia: patch 14/03/2017; WannaCry 12/05/2017; patch XP/2003/8 em 13/05; NotPetya 27/06/2017 via M.E.Doc — [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010), [MSRC](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks), [TA17-181A](https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware)
- WannaCry não dependia só de phishing (NCSC não viu evidência de phishing); o dropper varria faixas locais pelas portas SMB/NetBIOS — [NCSC](https://www.ncsc.gov.uk/blog-post/wannacry-ransomware-guidance-updates), [TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)
- Kill switch: o domínio de checagem parou a propagação quando resolvia; CISA recomenda não bloqueá-lo — [TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)
- NotPetya: criptografia irreversível, chave não vinculada à vítima — [TA17-181A](https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware)
- Estado em 2026 (Microsoft): SMBv1 fora do padrão no Windows 11/Server 2019+, signing obrigatório no 24H2/Server 2025, Credential Guard habilitado por padrão no 22H2+ domain-joined, roteiro NTLM com fase 3 sem data — [Microsoft Learn SMB](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening), [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/), [NTLM roadmap](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-security-disabling-ntlm-by-default/4489526)

### Inferences
Lições (síntese):
1. Patch em dias, não meses; com SLA e verificação de conformidade (NAO: sem verificação formal antes de 12/05).
2. Superfície mínima: remover SMBv1 e serviços de compartilhamento onde não necessários.
3. Egress/ingress em 445/139 e segmentação interna; plataformas sem suporte isoladas.
4. Proteger credenciais (LAPS, Credential Guard, PAM) e restringir PsExec/WMI/admin$.
5. Detecção em rede e endpoint; telemetria de auditoria SMB1 (3000/32002).
6. Backups offline testados; exercício de IR; comunicação alternativa ao e-mail (NAO apontou falha de comunicação).
7. Cadeia de suprimentos de software (M.E.Doc) como vetor de entrega; vale para atualizações de terceiros.
8. Desligar o legado: a falha estrutural é dependência de SO sem suporte.

Defesa em profundidade (quadro-resumo):

| Camada | Controle | Fase |
|---|---|---|
| Governança | Inventário, SLA de patch (NIST SP 800-40r4), gestão de legado/EOL | Prevenir |
| Host | MS17-010 e rollups atuais; SMB1 removido; signing; Credential Guard; LAPS; AV/EDR; firewall de host | Prevenir/Detectar |
| Rede | Bloqueio 445/139/137/138 in/out; VLAN/microssegmentação; isolamento de legado; IPS | Prevenir/Conter/Detectar |
| Identidade | Privilégio mínimo, MFA, admin separado, Kerberos em vez de NTLM | Conter |
| Dados | Backup 3-2-1 com cópia offline e teste de restauração | Recuperar |
| Operação | Plano de IR ensaiado, exercícios, notificação a CSIRT (CTIR Gov/CERT.br/CISA) | Detectar/Recuperar |

### Gaps
- Sem estimativa quantitativa de perdas globais de fontes primárias lidas (apenas NAO sobre NHS, e sem custo total).
- Não foi verificado se Windows 10 1703 tem KB próprio listado em MS17-010 (a tabela do boletim não o lista).
- Itens do enunciado não cobertos por fonte primária lida: "Kaspersky/Trend Micro/Check Point/Rapid7 (além do módulo)/SANS/Cloudflare/Imperva", CIS Controls, NIST SP 800-53.
