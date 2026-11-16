# Estatísticas e impacto medido do EternalBlue / MS17-010 (2017 a nov/2026)

Notas de pesquisa (dataset-style), em português; termos técnicos em inglês. Data de referência: 15/11/2026.

**Legenda de confiança:** ALTA = fonte primária (vendor/órgão) lida diretamente nesta pesquisa. MÉDIA = fonte secundária idônea, ou primária lida só em trecho. BAIXA = agregador, número só visto em snippet de busca, método não descrito, ou fonte com conflito. "Tipo de métrica" sempre indicado: detecções (eventos) vs. usuários únicos vs. máquinas/IPs vs. ataques bloqueados vs. estimativa econômica.

**Aviso metodológico geral:** nenhuma série pública contínua de "detecções de EternalBlue por ano" (2017–2026) foi localizada em formato numérico. Kaspersky, ESET e Trend Micro mostram a maior parte dos dados só em gráficos (sem valores no texto). Onde só há texto qualitativo, isso está registrado como tal e nenhum número foi inventado.

---

## 1. Danos financeiros (WannaCry, NotPetya, NHS e outros)

### Takeaway
As cifras globais de WannaCry (US$ 4 bi e depois ~US$ 8 bi, da Cyence) são estimativas de modelagem de risco, não perdas auditadas, e o número de US$ 10 bi do NotPetya é uma avaliação atribuída à Casa Branca via imprensa. Os únicos números "duros" são os divulgados por empresas (Merck, Maersk, Reckitt) e pelo governo britânico (NHS £92 mi). Parte dos danos do NotPetya não decorre só do MS17-010, porque o malware também usava roubo de credenciais.

### Cited Findings
**WannaCry (maio/2017)**
- Cyence (modelagem de risco cibernético) estimou o custo global em "até" US$ 4 bi; a matéria não descreve o método e nota que os atacantes arrecadaram menos de ~US$ 100 mil. Métrica: estimativa econômica de modelo. Confiança MÉDIA. — [CSO Online](https://www.csoonline.com/article/3345967/is-the-world-ready-for-the-next-big-ransomware-attack.html); [CBS News](https://cbsn.ws/3eU2vl1)
- Cyence elevou depois a estimativa de interrupção de negócios para cerca de US$ 8 bi (George Ng, co-fundador/CTO da Cyence), subindo dos US$ 4 bi iniciais. Reportado também via WSJ: o cálculo ponderou taxas médias de backup frente aos modelos de negócio das empresas, com recuperação de 1 a 12 horas. Confiança MÉDIA (fonte primária da Cyence não lida). — [CSO Online, "WannaCry fallout"](https://www.csoonline.com/article/3196400/wannacry-fallout-the-worst-is-yet-to-come-experts-say.html); [A.M. Best via Reinsurance News](https://www.reinsurancene.ws/reinsurance-take-minimal-share-8-billion-wannacry-economic-loss-m-best/)
- Ressalva de conflito: uma matéria da Reuters de jul/2017 (via The Star) descreve os US$ 8 bi como cobrindo "o ataque desta semana [NotPetya] e o de mês passado [WannaCry]", ou seja, pode ser WannaCry + NotPetya combinados; coberturas posteriores tratam US$ 8 bi como só WannaCry. Confiança BAIXA quanto à atribuição. — [The Star/Reuters](https://www.thestar.com.my/news/world/2017/06/28/second-major-cyber-attack-in-two-months-disrupts-businesses-around-world); [The Register](https://www.theregister.com/2017/07/18/cyber_calamity_costs)
- Receita dos atacantes: ~US$ 55 mil em bitcoin segundo estimativa da Kaspersky (contraste com bilhões de dano). — [Kaspersky Security Bulletin 2017](https://securelist.com/ksb-story-of-the-year-2017/83290/)

**NHS (Reino Unido)**
- O Department of Health and Social Care estimou o custo do WannaCry ao NHS em £92 mi (perda de produção e custos de TI), divulgado em out/2018; decomposição reportada: ~£19 mi durante o ataque (cancelamentos, perda de produtividade) e ~£72 mi em recuperação/IT posterior; cerca de 19.000 consultas canceladas. Método: estimativa governamental ("approximate"). Confiança ALTA para o valor total (fonte oficial replicada por vários veículos), MÉDIA para a decomposição. — [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/wannacry-cost-nhs-92-million/); [National Health Executive](https://www.nationalhealthexecutive.com/articles/wannacry-cyber-attack-cost-nhs-ps92m-after-19000-appointments-were-cancelled); [MobiHealthNews](https://www.mobihealthnews.com/news/emea/wannacry-attack-cost-nhs-estimated-ps92m-department-health-and-social-care-says)

**NotPetya (jun/2017)** (usou EternalBlue/EternalRomance para propagação lateral)
- Casa Branca (15/fev/2018) atribuiu o NotPetya ao exército russo e o chamou de "the most destructive and costly cyber-attack in history", com danos de "bilhões de dólares" (sem número exato no comunicado, conforme coberturas). — [Dark Reading](https://www.darkreading.com/threat-intelligence/white-house-russian-military-behind-notpetya-attacks/d/d-id/1331078); [Free Beacon](https://freebeacon.com/national-security/white-house-russias-attack-ukraine-destructive-costly-cyber-attack-history/)
- O número de "mais de US$ 10 bi" aparece em reportagem posterior da Wired (2018), atribuído a uma avaliação da Casa Branca (não o comunicado de fev/2018). Não consegui abrir a Wired (bloqueada); informação veio de resultados de busca. Confiança MÉDIA/BAIXA. — [resumo em Wired via índice](https://nocache.zinio.com/dk/publications/wired/6184/issues/401502/articles); [bad.technology (agregador, BAIXA)](https://bad.technology/articles/notpetya-wiper-disguised-as-ransomware-causes-10-billion-in-global-damage.html)
- Estimativa bem inferior: Cyberreason, a partir de resultados trimestrais e declarações a investidores das empresas afetadas, ~US$ 1,2 bi (somente perdas publicamente declaradas). — [CSO Online](https://www.csoonline.com/article/3345967/is-the-world-ready-for-the-next-big-ransomware-attack.html)
- Maersk: impacto negativo esperado de US$ 200–300 mi (declaração do Q2/2017, é estimativa da própria empresa); Kaspersky também cita ~US$ 300 mi de perda de receita. Confiança ALTA/MÉDIA. — [CSHub](https://www.cshub.com/attacks/news/notpetya-costs-merck-fedex-maersk-800m); [Securelist KSB 2017](https://securelist.com/ksb-story-of-the-year-2017/83290/)
- Merck: US$ 135 mi de vendas perdidas + US$ 175 mi de custos adicionais (divulgado em teleconferência, out/2017); estimativa de ~US$ 870 mi de dano total (disrupção e arquivos criptografados) em registros; reivindicou US$ 1,3–1,4 bi às seguradoras. Em 2022 (trial court) e 2023 (appellate NJ) ganhou contra seguradoras que invocavam a exclusão de "ato de guerra"; em 2024 houve acordo confidencial (valor não divulgado). US$ 1,4 bi é o valor reclamado, não pago. Confiança MÉDIA. — [CSHub](https://www.cshub.com/attacks/news/notpetya-costs-merck-fedex-maersk-800m); [The Record](https://therecord.media/merck-insurance-settlement-notpetya); [Insurance Business](https://www.insurancebusinessmag.com/au/news/cyber/pharma-giant-merck-and-insurers-settle-1-4-billion-notpetya-case-471920.aspx)
- FedEx (TNT): fontes divergem. CSHub/CSO falam em ~US$ 300 mi; outra fonte em US$ 400 mi para a TNT. A FedEx não deu número no momento do ataque. O usuário citou US$ 400 mi; não consegui confirmar em documento da FedEx (10-K) nesta pesquisa. Confiança BAIXA. — [CSHub](https://www.cshub.com/attacks/news/notpetya-costs-merck-fedex-maersk-800m); [CSO Online](https://www.csoonline.com/article/3345967/is-the-world-ready-for-the-next-big-ransomware-attack.html)
- Reckitt Benckiser: perdeu acesso a 15.000 notebooks, 2.000 servidores e 500 sistemas em 45 minutos; custo esperado acima de US$ 130 mi. Fonte Kaspersky. Confiança MÉDIA. — [Securelist KSB 2017](https://securelist.com/ksb-story-of-the-year-2017/83290/)
- Mondelez: Zurich recusou uma reivindicação de US$ 100 mi (exclusão de "hostile or warlike action"); acordo em 2022 sem valor divulgado. Um listão baseado na Wired cita US$ 188 mi para a Mondelez (BAIXA, secundário). — [CSO Online](https://www.csoonline.com/article/3345967/is-the-world-ready-for-the-next-big-ransomware-attack.html); [The Record/outros](https://therecord.media/merck-insurance-settlement-notpetya)

**Outros**
- Bad Rabbit (out/2017) usou EternalRomance (não EternalBlue); atingiu perto de 200 alvos na Rússia, Ucrânia, Turquia e Alemanha (Kaspersky ICS CERT). Impacto financeiro não localizado. — [Kaspersky ICS CERT](https://ics-cert.kaspersky.com/publications/bad-rabbit/)
- Cyberattacks em geral (CEA, Casa Branca, fev/2018): atividade cibernética maliciosa custou à economia dos EUA entre US$ 57 bi e US$ 109 bi em 2016 (contexto; não é específico de EternalBlue). — [Business Insurance](https://www.businessinsurance.com/malicious-cyber-activity-cost-us-up-to-109-billion-in-2016-white-house-says/)

### Inferences
- A faixa de WannaCry de US$ 4 bi a US$ 8 bi deve ser apresentada como "estimativa de modelo de seguradora", não como perda medida. Já o NotPetya tem pelo menos 3 ordens de grandeza de metodologia: US$ 1,2 bi (somas de perdas declaradas), ~US$ 10 bi (avaliação governamental) e perdas individuais bem documentadas (Merck ~US$ 870 mi, Maersk US$ 200–300 mi).
- O NotPetya combina EternalBlue/EternalRomance com roubo de credenciais; portanto atribuir todo o custo ao MS17-010 superestima o papel da vulnerabilidade (inferência a partir da descrição técnica; o relatório de segurança deve citar uma fonte técnica).
- O custo ao NHS (£92 mi) é um dos poucos números oficiais e com decomposição, bom candidato a gráfico de barras com a ressalva de ser uma estimativa governamental.

### Gaps
- Não encontrei o relatório original da Cyence (só reportagens). Não confirmei o texto do comunicado da Casa Branca nem o número exato de US$ 10 bi na Wired (acesso bloqueado). Não confirmei FedEx/TNT US$ 400 mi em documento primário. Não localizei custo de WannaCry para Renault/Nissan/Telefónica etc., nem estimativas posteriores (2020–2026) revistas.

---

## 2. Contagens de infecção/ataque (WannaCry, DoublePulsar, detecções por fornecedor)

### Takeaway
WannaCry atingiu mais de 200.000 vítimas em mais de 150 países (Europol, maio/2017). Depois, as contagens de EternalBlue de vendors são quase todas "usuários únicos" ou "tentativas" e quase sempre só em gráficos. Os números verificáveis mostram atividade crescente até 2019 (ESET: máximo histórico; Kaspersky: >2 mi usuários em 12 meses até maio/2018) e queda gradual depois, mas sem série numérica pública contínua.

### Cited Findings
**WannaCry, 2017**
- Europol (Rob Wainwright, 14/mai/2017): mais de 200.000 vítimas em pelo menos 150 países. Métrica: "vítimas/alvos" (alguns veículos dizem "targets"). Confiança ALTA para o número divulgado, métrica imprecisa. — [Al Jazeera](https://www.aljazeera.com/news/2017/5/14/ransomware-attack-hit-200000-victims-in-150-countries); [Yahoo/Independent](https://www.yahoo.com/news/nhs-cyber-attack-ransomware-hits-101800660.html)
- Kaspersky (15/mai/2017): mais de 45.000 usuários atacados (só base de clientes Kaspersky); sinkhole do kill-switch (MalwareTech) registrou ~200.000 acessos, excluindo redes corporativas atrás de proxy. Confiança ALTA. — [Kaspersky WannaCry update](https://www.kaspersky.co.in/about/press-releases/kaspersky-lab-wannacry-threat-update-monday-morning-15th-may)
- Kaspersky (retrospectiva 2017): "centenas de milhares" de computadores afetados, até ~750 mil segundo relatos, ~727.000 IPs únicos não protegidos (estimativa); 2017 teve pouco menos de 950.000 usuários únicos atacados por ransomware (vs ~1,5 mi em 2016). Confiança MÉDIA. — [Securelist KSB 2017](https://securelist.com/ksb-story-of-the-year-2017/83290/)
- Check Point Global Threat Impact Index (maio/2017): WannaCry afetou ~8% das organizações no mundo (3º lugar, atrás de Fireball ~20% e RoughTed 16%). Métrica: % de organizações com ao menos um ataque detectado. Confiança ALTA. — [Check Point press release](https://checkpoint.com/press-releases/fireball-wannacry-impact-1-4-organizations-globally-according-check-points-latest-threat-index); [blog Check Point](https://blog.checkpoint.com/research/mays-wanted-malware-fireball-wannacry-impact-1-4-organizations-globally/)
- Kaspersky (testes de invasão em empresas, 2017): a vulnerabilidade MS17-010 foi detectada em 75% das empresas submetidas a pentest interno após a divulgação (via resumo de busca do comunicado Kaspersky). Confiança MÉDIA. — [Kaspersky press release](https://www.kaspersky.com/about/press-releases/corporate-network-penetration-tests-in-2017)
- Kaspersky (NotPetya/ExPetr): mais de 5.000 usuários atacados pela telemetria; principalmente Ucrânia, Rússia e Europa Ocidental. Confiança ALTA. — [Securelist KSB 2017](https://securelist.com/ksb-story-of-the-year-2017/83290/)

**DoublePulsar (implante da NSA vazado, abril/2017) — contagens de hosts por varredura**
- Dan Tentler (Phobos), varredura preliminar via Shodan em 20/abr/2017: 15.196 infecções (cerca de 4/5 em IPs dos EUA); Robert Graham: ~41.000 hosts em varredura maior. — [The Register, 21/04/2017](https://www.theregister.com/2017/04/21/windows_hacked_nsa_shadow_brokers/)
- CyberScoop (21/abr/2017): Tentler 30.000–50.000 (sem método); John Matherly (Shodan) projetou ~100.000 dispositivos (extrapolação: 0,04% de >2 mi IPs com SMB/445) e disse ter "45k infecções confirmadas" indexadas; Below0Day: ~35.000 em varredura de 18/abr (10 h de coleta; maioria nos EUA) e 30.626 em 20/abr. — [CyberScoop](https://cyberscoop.com/fast-thousands-computers-now-compromised-leaked-nsa-tools-researchers-say/)
- Resumos de busca (BankInfoSecurity, Threatpost; BAIXA/MÉDIA porque não abri o texto): Kevin Beaumont ~11% dos endpoints com SMB (≥20.000); Tentler em 23/abr: 33.468 em 1,17 mi hosts; BinaryEdge: de 106.410 para 183.107 máquinas entre 21 e 24/abr; Below0Day 21/abr: 56.586. — [BankInfoSecurity](https://www.bankinfosecurity.com/doublepulsar-pwnage-attackers-tap-equation-group-exploit-a-9859); [Threatpost](https://threatpost.com/nsas-doublepulsar-kernel-exploit-in-use-internet-wide/125165)
- Ressalvas dos autores: DoublePulsar roda em memória e o método (ping especial na porta 445) pode subestimar; presença do implante não implica que foi instalado pela NSA; Microsoft duvidou da precisão inicial. Os números variam por scanner, data e cobertura de hosts, então não são diretamente comparáveis. — [The Register](https://www.theregister.com/2017/04/21/windows_hacked_nsa_shadow_brokers/); [CyberScoop](https://cyberscoop.com/fast-thousands-computers-now-compromised-leaked-nsa-tools-researchers-say/)

**Kaspersky 2018–2024**
- Mai/2017 a mai/2018: mais de 2 milhões de usuários atacados via EternalBlue; abril/2018 foi 10x maior que maio/2017 (usuários únicos); média >240.000 usuários/mês. Métrica: usuários únicos de produtos Kaspersky com detecção do exploit. Confiança ALTA (relatado em 11/mai/2018). — [SecurityWeek](https://www.securityweek.com/one-year-after-wannacry-outbreak-eternalblue-exploit-still-threat/)
- Q3/2018: WannaCry atacou 74.621 usuários únicos (28,72% dos usuários atacados por cryptors; em Q3/2017 era 16,78%); total de usuários protegidos contra cryptors 259.867 (+39% vs. 158.921 no Q2/2018). Press release de 12/nov/2018. Confiança ALTA. — [Kaspersky press release](https://www.kaspersky.com/about/press-releases/wannacry-is-still-alive-hitting-almost-75000-users-in-q3-2018)
- Q1/2019: WannaCry foi a família de ransomware mais comum (Trojan-Ransom.Win32.Wanna), com 26,25% dos usuários atacados por ransomware; Kaspersky diz que os ataques do kit FuzzBunch (EternalBlue, EternalRomance etc.) "ainda ocupam todas as posições do topo" nas estatísticas de ataques de rede. Sem número absoluto para EternalBlue. Confiança ALTA. — [Securelist Q1 2019](https://securelist.com/it-threat-evolution-q1-2019-statistics/90916/)
- 2019: WannaCry 21,85% dos usuários que encontraram crypto-ransomware (1º lugar); 2020: 16% ou 80.207 usuários únicos (1º lugar). Métrica: usuários únicos de KSN que encontraram a família. Confiança ALTA. — [Securelist, Ransomware by the numbers](https://securelist.com/ransomware-by-the-numbers-reassessing-the-threats-global-impact/101965/)
- Página de ameaça Kaspersky "Exploit.Win32.MS17-010" (sem período declarado): top países por % de usuários atacados: Rússia 18,14%, Vietnã 17,44%, Irã 10,28%, China 8,76%, Indonésia 7,37%, Bangladesh 5,63%, Índia 5,59%, Turquia 3,19%, Tailândia 2,68%, Egito 2,22%. Brasil não aparece no top 10. Confiança MÉDIA (período indefinido). — [Kaspersky Threats](https://threats.kaspersky.com/en/threat/Exploit.Win32.MS17-010/)
- 2023: Q1, Q2 e Q3/2023, só texto qualitativo: "entre os exploits para vulnerabilidades de sistema operacional, EternalBlue e EternalRomance continuam populares" (sem números). Verificado diretamente no Q3/2023. — [Securelist Q3 2023](https://securelist.com/it-threat-evolution-q3-2023-non-mobile-statistics/111228/)
- 2024: o KSB 2024 não menciona EternalBlue/WannaCry; só o total de ransomware: 303.298 usuários únicos protegidos (não é métrica de EternalBlue). — [Securelist KSB 2024](https://securelist.com/ksb-2024-statistics/114795/)
- Painel ao vivo da Kaspersky (sem data na captura): variante Intrusion.Win.MS17-010.o ~5,12% e .p ~0,52% dos usuários com detecção de ataque de rede (snapshot não datado). Confiança BAIXA. — [statistics.securelist.com](https://statistics.securelist.com/intrusion-detection-scan/day)

**ESET**
- Mai/2019 (ESET LiveGrid): centenas de milhares de tentativas de exploit EternalBlue bloqueadas por dia; "milhares" de clientes únicos por dia; descreve o nível como "picos históricos". Valores exatos só em gráficos. Confiança MÉDIA. — [WeLiveSecurity, 17/05/2019](https://welivesecurity.com/2019/05/17/eternalblue-new-heights-wannacryptor/)
- Mai/2020: WannaCryptor era 40,5% das detecções de ransomware no Q1/2020 (ESET Threat Report); detecções de tentativa de ataque no fim do Q1/2020 eram metade do pico histórico do Q2/2019; ainda "centenas de milhares" por dia. Confiança ALTA para o texto (números exatos não divulgados). — [WeLiveSecurity, 12/05/2020](https://www.welivesecurity.com/2020/05/12/wannacryptor-remains-global-threat-three-years-on/)
- (Resumo de busca, BAIXA) a ESET observou pico de detecções entre fev. e mar/2019; o texto do artigo de maio/2019 não afirma essa janela literalmente. — [SC Media](https://www.scworld.com/news/attempted-cyberattacks-using-eternalblue-exploit-soar-in-recent-months)

**Trend Micro**
- Out/2019: rastreou detecções de maio/2017 a set/2019 (Smart Protection Network); em 2019 as detecções de WannaCry são quase 4x as de todo o resto do ransomware somado; a maior parte do malware não-WannaCry com EternalBlue em 2019 era mineração de criptomoedas; os valores numéricos estão só nos gráficos. Confiança MÉDIA. — [Trend Micro](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/putting-the-eternal-in-eternalblue-mapping-the-use-of-the-infamous-exploit)
- Resumo de busca cita 73.763 detecções de amostras conhecidas de malware que usam EternalBlue em 2019 (fonte secundária; número não encontrado no texto do artigo que li). Confiança BAIXA. — [resultado de busca sobre o artigo Trend Micro](https://trendmicro.com/vinfo/br/security/news/vulnerabilities-and-exploits/putting-the-eternal-in-eternalblue-mapping-the-use-of-the-infamous-exploit)

**F-Secure (honeypots)**
- H1/2019: 556 milhões de eventos de tentativa de exploração contra SMB (porta 445), atribuídos a exploits como EternalBlue (via cobertura; período provável H1/2019). Métrica: eventos em honeypots. Confiança BAIXA/MÉDIA. — [F-Secure blog](https://blog.f-secure.com/attack-landscape-h1-2019-iot-smb-traffic-abound)
- F-Secure (cobertura de 2020, segunda mão): o exploit mais visto continuava sendo contra SMBv1/EternalBlue. Confiança BAIXA. — [BankInfoSecurity](https://www.bankinfosecurity.com/blogs/does-eternalblue-targeting-wannacry-remain-at-large-p-3002)

**Sistemas operacionais atingidos em 2017**
- Kaspersky (via Dark Reading, resumo de busca; não consegui abrir a matéria, 403): ~95% dos dispositivos infectados rodavam Windows 7 (60% Windows 7 x64). Confiança BAIXA/MÉDIA. — [Dark Reading](https://darkreading.com/threat-intelligence/wannacry-hit-windows-7-machines-most)

### Inferences
- Pela sequência de dados verificáveis (Kaspersky mai/2017–mai/2018: >240 mil usuários/mês; ESET: pico em 2019 e queda para ~50% do pico no 1º trim./2020), o período de maior intensidade de EternalBlue foi 2018–2019, não 2017. Isto é uma inferência baseada em gráficos descritos e não em valores numéricos.
- Para qualquer gráfico de "detecções por ano" será preciso ler os gráficos dos relatórios diretamente (ESET, Trend) e anotar como estimativa visual; o texto não traz os valores.

### Gaps
- Sem números anuais de EternalBlue da Kaspersky para 2019–2025 (apenas texto qualitativo e shares de WannaCry). Sem contagens Avast ou Microsoft Security Intelligence de EternalBlue (não localizadas). Sem série numérica da Check Point para MS17-010 por ano (veja seção 4). Adylkuzz: nenhum número de infectados achado. Kaspersky Bad Rabbit: ~200 alvos apenas.

---

## 3. Exposição de SMBv1 / porta 445 e sistemas sem patch ao longo do tempo

### Takeaway
Houve queda de milhões de hosts SMB expostos em 2017 para algo em torno de 1 milhão de máquinas SMBv1 em 2019–2020 (Shodan), mas não há série confiável de "hosts vulneráveis ao MS17-010" depois de 2020. Sem dados primários para 2021–2026 (Shadowserver publica o relatório "Accessible SMB" diariamente, mas não obtive os números).

### Cited Findings
- 2017: pesquisa citada pela SecurityLab (mid-2017) encontrou ~2,3 milhões de hosts SMB expostos, 96% (>2,2 mi) com SMBv1. Confiança BAIXA/MÉDIA (secundário, resumo de busca). — [SecurityLab.ru](https://www.securitylab.ru/news/486738.php)
- 2017: Imperva (resumo de busca): ~537.000 hosts respondendo na 445 e ~60.000 vulneráveis ao EternalBlue (1 em 9). Confiança BAIXA. — [GovInfoSecurity (scanner EternalBlue)](https://www.govinfosecurity.com/blogs/eternally-blue-scanner-finds-eternalblue-still-widespread-p-2512)
- Mai/2018: Juniper Networks reportava ~2,3 milhões de dispositivos com SMBv1 exposto à internet, majoritariamente nos Emirados Árabes Unidos, EUA, Rússia, Taiwan e Japão (métrica: dispositivos expostos, não infectados). Confiança MÉDIA. — [SecurityWeek](https://www.securityweek.com/one-year-after-wannacry-outbreak-eternalblue-exploit-still-threat/)
- Mai/2019: Shodan mostrava quase 1 milhão de máquinas com SMBv1 na 445 exposta; EUA, depois Japão, depois Rússia. Confiança MÉDIA. — [WeLiveSecurity](https://welivesecurity.com/2019/05/17/eternalblue-new-heights-wannacryptor/)
- 4/mai/2020: ~1 milhão de máquinas Windows com SMBv1 expostas (Shodan, citado pela ESET); ranking: EUA 1º, Rússia ultrapassou o Japão, África do Sul entrou entre os primeiros. Métrica: expostas, não confirmadas vulneráveis. Confiança MÉDIA. — [WeLiveSecurity](https://www.welivesecurity.com/2020/05/12/wannacryptor-remains-global-threat-three-years-on/)
- Mar/2020: Rapid7 (citado por CybelAngel, secundário): entre 500.000 e 1,3 mi dispositivos executavam SMB; ~343.000 com SMBv1 e autenticação desativada, a maioria Unix e não Windows. Confiança BAIXA. — [CybelAngel](https://cybelangel.com/blog/smbv1-still-a-threat/)
- Securin (sem data): 8.601 dispositivos "extremamente vulneráveis" ao EternalBlue em análise Shodan. Confiança BAIXA (sem data). — [Securin](https://www.securin.io/articles/indexsinas-smb-worm-exploits-eternalblue-vulnerabilities)
- Shadowserver mantém o relatório "Accessible SMB" (scan_smb), severidade HIGH, atualizado a cada 24 h, com descrição revisada em 27/12/2023; os números estão no painel, mas não obtive valores. — [Shadowserver](https://www.shadowserver.org/hp-rewrite/c5762b0b0067c56383f8b6ee14a1b3c5)
- Kaspersky (testes de invasão): MS17-010 presente em 75% das empresas pentestadas após a divulgação (2017). — ver seção 2.
- Participação de Windows 7 (StatCounter, tráfego web, não instalação; secundário): ~13,8% dos desktops em dez/2020; ~3,04% em mar/2024; ~2,85% em out/2024; ~3,35–3,59% em ago/2025; 9,61% em set/2025, considerado anomalia pela imprensa. Confiança BAIXA (números vieram de coberturas de imprensa). — [Windows Latest](https://windowslatest.com/2025/10/02/no-windows-7-isnt-gaining-market-share-in-2025); [Neowin](https://www.neowin.net/news/windows-7-marketshare-jumps-to-nearly-10-as-windows-10-enters-final-weeks-of-support/); [BornCity](https://borncity.com/win/2024/10/03/operating-system-windows-share-october-2023/); [TechRadar](https://www.techradar.com/pro/windows-11-market-share-slips-worryingly-as-windows-7-and-windows-10-record-growth-against-expectations)

### Inferences
- Janela de exposição "anunciada": de ~2,3 mi (2017–2018) para ~1 mi (2019–2020) de hosts com SMBv1 expostos mostra redução de ~55%, mas medida por scanners diferentes (Juniper vs. Shodan), então não comparar como série única.
- Em 2020 o exposto era majoritariamente "SMBv1 aberto", e isso não equivale a "vulnerável ao MS17-010"; muitos eram Unix/Samba.

### Gaps
- Sem Censys, BinaryEdge ou Rapid7 Project Sonar primários nesta pesquisa. Sem contagens de hosts MS17-010 vulneráveis para 2021–2026. Sem dados de Windows XP/Server 2008/2008 R2 em uso (StatCounter só mede web desktop; nenhuma fonte de servidores achada). Sem dado do Microsoft Digital Defense Report sobre EternalBlue.

---

## 4. Persistência: CVE-2017-0144 em rankings (CISA, KEV, Check Point etc.), 2021–2026

### Takeaway
O registro mais forte e verificável de persistência é o CISA KEV: CVE-2017-0144 foi adicionado em 10/02/2022 (prazo 10/08/2022) com uso conhecido em campanhas de ransomware, e continuava no catálogo em 13/11/2026. Os rankings "Top Routinely Exploited" que consegui verificar não listam CVE-2017-0144 diretamente. Não achei lista da Check Point com MS17-010 com percentual.

### Cited Findings
- CISA KEV (feed JSON consultado em 15/11/2026, catalogVersion 2026.11.13, 1.781 entradas): CVE-2017-0144 "Microsoft SMBv1 Remote Code Execution Vulnerability", dateAdded 2022-02-10, dueDate 2022-08-10, knownRansomwareCampaignUse = Known. Confiança ALTA. — [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- Demais CVEs da família no KEV (todos "Known" para ransomware): CVE-2017-0143 (adicionado 2021-11-03, prazo 2022-05-03, com o lote inicial do BOD 22-01), CVE-2017-0145 (2022-02-10, prazo 2022-08-10), CVE-2017-0146 (2022-03-25, prazo 2022-04-15), CVE-2017-0148 (2022-04-06, prazo 2022-04-27), CVE-2017-0147 (2022-05-24, prazo 2022-06-14). Confiança ALTA. — [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- A adição de 10–11/fev/2022 (15 CVEs) foi coberta pela mídia, incluindo o CVE-2017-0144. — [CSO Online](https://www.csoonline.com/article/3649991/cisa-warns-about-15-actively-exploited-vulnerabilities.html)
- CISA AA20-133A ("Top 10 Routinely Exploited Vulnerabilities", maio/2020): a lista de 2016–2019 inclui CVE-2017-0143 (SMBv1, associada a EternalSynergy/EternalBlue); CVE-2017-0144 NÃO consta; a seção de 2020 cobre CVE-2019-11510, CVE-2019-19781 e configurações de O365 e não lista CVE de SMB. Confiança ALTA. — [CISA AA20-133A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-133a)
- CISA/FBI/NSA AA22-117A (abr/2022): a página de comunicado que li não cita CVEs; não verifiquei a lista no PDF do aviso. Não posso afirmar presença ou ausência de CVE-2017-0144. — [CISA press release](https://cisa.gov/news/2022/04/27/cisa-fbi-nsa-and-international-partners-warn-organizations-top-routinely-exploited)
- Check Point (27/out/2020, lista NSA Top 25): ~3 mi de tentativas nos últimos 12 meses, 161 países; não cita MS17-010/EternalBlue. Check Point (blog sobre CISA Top 15 de 2021): também não menciona CVE-2017-0144/SMB. — [Check Point blog (NSA top 25)](https://blog.checkpoint.com/security/measuring-the-global-impact-of-the-nsas-top-25-vulnerabilities-being-exploited-in-the-wild/); [Check Point blog (CISA 2021)](https://blog.checkpoint.com/security/cisas-2021-top-15-routinely-exploited-vulnerabilities-check-point-customers-remain-fully-protected/)
- Check Point (2023): vulnerabilidades reportadas nos 3 anos anteriores foram usadas em 24% das tentativas de exploração em 2022 (vs. 18% em 2021), com destaque para outras CVEs, e sem menção a MS17-010 no resumo lido. — [Check Point blog 2023](https://blog.checkpoint.com/2023/03/30/top-vulnerabilities-in-2023-and-how-to-block-them/)
- Ransomware usando MS17-010 (RiskSense 2019, via Help Net Security): MS17-010 usado em Ryuk, SamSam, Satan, entre outras famílias. Confiança MÉDIA. — [Help Net Security](https://www.helpnetsecurity.com/2019/09/25/vulnerabilities-ransomware/)
- Recorded Future (2018): o exploit ETERNALBLUE, embora muito citado, não era oferecido em exploit kits do submundo. Confiança MÉDIA. — [Recorded Future](https://www.recordedfuture.com/blog/top-vulnerabilities-2018)
- Kaspersky 2023 (Q1–Q3): "EternalBlue e EternalRomance continuam populares" entre os exploits de SO; sem números. — [Securelist Q3 2023](https://securelist.com/it-threat-evolution-q3-2023-non-mobile-statistics/111228/)
- F-Secure (2020, via cobertura): EternalBlue/SMBv1 seguia como exploit mais visto. Confiança BAIXA. — [BankInfoSecurity](https://www.bankinfosecurity.com/blogs/does-eternalblue-targeting-wannacry-remain-at-large-p-3002)

### Inferences
- A entrada no KEV em 2021–2022, quatro a cinco anos após o patch, indica que CISA tinha evidência de exploração ativa; combinada com "Known" para ransomware, comprova persistência até ao menos 2022. Para 2023–2026, a evidência é o fato de continuar no KEV e o texto qualitativo da Kaspersky.
- A ausência do CVE-2017-0144 na lista AA20-133A (que lista a 0143) reflete a metodologia dessas listas (CVEs mais citados nos relatos), e não necessariamente uso menor; sem validação.

### Gaps
- Check Point Global Threat Index/Cyber Attack Trends: não achei a % de organizações para MS17-010 por ano (resumos de busca falharam; PDFs completos de 2018–2021 não lidos). Não verifiquei AA21-209A nem AA22-117A, AA23-215A, AA24-... (listas posteriores) quanto a CVE-2017-0144. Sem relatórios Cisco Talos, Cloudflare ou Microsoft Digital Defense Report com números de MS17-010 em 2021–2026. Uma página da Wikipedia sobre o "Coruna exploit kit" menciona observação em 2025, sem verificação (descartada).

---

## 5. Dados específicos do Brasil

### Takeaway
Dados de Brasil são escassos e quase todos de 2017: 13º lugar no ranking Kaspersky no primeiro dia do WannaCry (12/mai/2017), 5º lugar no ranking Avast (métricas diferentes), e 55% dos ataques de ransomware reportados na América Latina em 2017 (Kaspersky). Não achei dados do CERT.br nem dados brasileiros de EternalBlue para 2018–2026.

### Cited Findings
- Kaspersky, 12/mai/2017 (dados até a tarde): Brasil em 13º lugar em número de PCs afetados pelo WannaCry (a Rússia liderou "de longe"); total >45.000 computadores em 74 países. O número absoluto do Brasil está só na imagem do ranking. Confiança MÉDIA. — [Olhar Digital](https://olhardigital.com.br/noticia/entenda-o-ciberataque-que-afetou-mais-de-45-mil-pcs-em-74-paises/68253)
- Avast (15/mai/2017, 07h38 de Brasília): Brasil com 17,56% de dispositivos vulneráveis ao WannaCry (definição de "vulnerável" não explicada), 2.114 detecções de ransomware e 5º lugar em detecção de worms (a própria matéria é inconsistente na lista de países à frente). Os dados são da Avast, não da ESET (nota: a ESET só aparece como fonte de >200.000 sistemas infectados e ~US$ 50 mil arrecadados). Confiança BAIXA/MÉDIA. — [Convergência Digital](https://convergenciadigital.com.br/?p=7869)
- Olhar Digital (especial): relatório da Avast coloca o Brasil em 5º entre os mais afetados. — [Olhar Digital](https://olhardigital.com.br/especial/wannacry/)
- Kaspersky (setembro/2017, América Latina): ataques de ransomware cresceram 30% entre 2016 e 2017; 57.512 detecções em 2016 e 24.110 no ano até a data da matéria; o Brasil concentra 55% dos ataques de ransomware reportados na região, seguido pelo México (23,40%) e Colômbia (5%); WannaCry se espalhou mais no México e no Brasil, depois Chile, Equador, Colômbia. Confiança MÉDIA. — [Hardware.com.br](https://www.hardware.com.br/?p=147308)
- Kaspersky (15/mai/2017): as três primeiras vítimas da primeira variante conhecida do WannaCry estavam na Rússia e no Brasil. — [Kaspersky WannaCry update](https://www.kaspersky.co.in/about/press-releases/kaspersky-lab-wannacry-threat-update-monday-morning-15th-may)
- Europol citou o Brasil entre os países atingidos em 2017. — [Al Jazeera](https://www.aljazeera.com/news/2017/5/14/ransomware-attack-hit-200000-victims-in-150-countries)
- Kaspersky Exploit.Win32.MS17-010 (sem período): Brasil não está entre os 10 primeiros países. Securelist Q1 2019 e Q3 2023: nenhuma estatística de WannaCry/EternalBlue por país com o Brasil. — [Kaspersky Threats](https://threats.kaspersky.com/en/threat/Exploit.Win32.MS17-010/); [Securelist Q3 2023](https://securelist.com/it-threat-evolution-q3-2023-non-mobile-statistics/111228/)
- Dados gerais de ransomware (não específicos de WannaCry), apenas como contexto: Kaspersky bloqueou >487 mil ataques de ransomware no Brasil entre jun/2023 e jul/2024 (via resumo de busca, BAIXA). — [DCD Brasil](https://www.datacenterdynamics.com/br/not%C3%ADcias/brasil-segue-como-o-pais-mais-atacado-por-ransomware-na-america-latina/)

### Inferences
- Rankings de 13º (Kaspersky, PCs afetados) e 5º (Avast, detecção de worms/ vulneráveis) não são contraditórios; medem coisas diferentes (base de usuários de cada fornecedor).
- O Brasil figura mais em ransomware em geral (55% da América Latina) do que em EternalBlue em particular.

### Gaps
- Nenhum dado do CERT.br sobre WannaCry/EternalBlue localizado (o CERT.br não foi consultado diretamente). Nenhum dado brasileiro de exposição SMBv1/445 (Shodan/Censys) nem de detecções de EternalBlue para 2018–2026. Os artigos de 2017 não trazem valores absolutos legíveis no texto (ranking em imagem). Um artigo da SBC (sol.sbc.org.br SBSeg) apareceu na busca, mas não foi aberto.

---

## 6. Tabela ano a ano (2017–2026): melhores métricas disponíveis

### Takeaway
Para 2017–2020 há métricas quantitativas razoáveis (a maioria em "usuários únicos" ou "% de usuários"); para 2021–2026 só há indicadores qualitativos e a presença no KEV. Células vazias ("n/d") significam que não foi encontrado número sourced, não que o valor seja zero.

### Cited Findings
| Ano | Métrica / valor | Tipo de métrica | Fonte | Confiança |
|---|---|---|---|---|
| 2017 | WannaCry: >200.000 vítimas, ≥150 países (14/mai) | vítimas/alvos (Europol) | [Al Jazeera](https://www.aljazeera.com/news/2017/5/14/ransomware-attack-hit-200000-victims-in-150-countries) | ALTA (número), métrica imprecisa |
| 2017 | WannaCry: >45.000 usuários atacados Kaspersky (15/mai); ~200.000 hits no sinkhole | usuários únicos / hits de DNS | [Kaspersky](https://www.kaspersky.co.in/about/press-releases/kaspersky-lab-wannacry-threat-update-monday-morning-15th-may) | ALTA |
| 2017 | DoublePulsar abr/2017: 15.196 (20/abr) a ~183.107 (24/abr) hosts conforme o scanner | hosts com implante | [Register](https://www.theregister.com/2017/04/21/windows_hacked_nsa_shadow_brokers/); [BankInfoSecurity](https://www.bankinfosecurity.com/doublepulsar-pwnage-attackers-tap-equation-group-exploit-a-9859) | MÉDIA (varia por scanner) |
| 2017 | WannaCry ~8% das organizações no mundo (maio) | % de organizações | [Check Point](https://checkpoint.com/press-releases/fireball-wannacry-impact-1-4-organizations-globally-according-check-points-latest-threat-index) | ALTA |
| 2017 | Custo WannaCry: US$ 4 bi → ~US$ 8 bi (Cyence); NHS £92 mi (divulgado 2018) | estimativa de modelo / estimativa governamental | [CSO](https://www.csoonline.com/article/3196400/wannacry-fallout-the-worst-is-yet-to-come-experts-say.html); [Infosecurity](https://www.infosecurity-magazine.com/news/wannacry-cost-nhs-92-million/) | MÉDIA / ALTA |
| 2017 | NotPetya: >5.000 usuários atacados (Kaspersky); Maersk US$ 200–300 mi; Merck ~US$ 870 mi; Reckitt >US$ 130 mi | usuários únicos / perdas declaradas | [Securelist](https://securelist.com/ksb-story-of-the-year-2017/83290/); [CSHub](https://www.cshub.com/attacks/news/notpetya-costs-merck-fedex-maersk-800m) | MÉDIA/ALTA |
| 2017 | SMB exposto: ~2,3 mi hosts, 96% SMBv1 (meados) | hosts expostos | [SecurityLab](https://www.securitylab.ru/news/486738.php) | BAIXA/MÉDIA |
| 2017 | Brasil: 13º (Kaspersky, 12/mai); 2.114 detecções ransomware e 17,56% vulneráveis (Avast, 15/mai); 55% do ransomware na LatAm | ranking de PCs / detecções / % regional | [Olhar Digital](https://olhardigital.com.br/noticia/entenda-o-ciberataque-que-afetou-mais-de-45-mil-pcs-em-74-paises/68253); [Convergência Digital](https://convergenciadigital.com.br/?p=7869); [Hardware.com.br](https://www.hardware.com.br/?p=147308) | MÉDIA/BAIXA |
| 2018 | EternalBlue: >2 mi usuários únicos atacados (mai/2017–mai/2018); abr/2018 = 10x mai/2017; >240.000/mês | usuários únicos (Kaspersky) | [SecurityWeek](https://www.securityweek.com/one-year-after-wannacry-outbreak-eternalblue-exploit-still-threat/) | ALTA |
| 2018 | WannaCry Q3/2018: 74.621 usuários únicos; 28,72% dos usuários atacados por cryptors | usuários únicos | [Kaspersky](https://www.kaspersky.com/about/press-releases/wannacry-is-still-alive-hitting-almost-75000-users-in-q3-2018) | ALTA |
| 2018 | SMBv1 exposto: ~2,3 mi dispositivos (Juniper) | dispositivos expostos | [SecurityWeek](https://www.securityweek.com/one-year-after-wannacry-outbreak-eternalblue-exploit-still-threat/) | MÉDIA |
| 2018 | NotPetya: Casa Branca "bilhões" (fev); ">US$ 10 bi" (Wired, 2018); Cyberreason US$ 1,2 bi | estimativa econômica | [Dark Reading](https://www.darkreading.com/threat-intelligence/white-house-russian-military-behind-notpetya-attacks/d/d-id/1331078); [CSO](https://www.csoonline.com/article/3345967/is-the-world-ready-for-the-next-big-ransomware-attack.html) | MÉDIA/BAIXA |
| 2019 | ESET: centenas de milhares de tentativas/dia; picos históricos (mai); ~1 mi máquinas SMBv1 (Shodan) | tentativas bloqueadas/dia; hosts expostos | [WeLiveSecurity](https://welivesecurity.com/2019/05/17/eternalblue-new-heights-wannacryptor/) | MÉDIA |
| 2019 | WannaCry: 26,25% dos usuários atacados por ransomware (Q1); 21,85% no ano | % de usuários únicos | [Securelist Q1 2019](https://securelist.com/it-threat-evolution-q1-2019-statistics/90916/); [Securelist](https://securelist.com/ransomware-by-the-numbers-reassessing-the-threats-global-impact/101965/) | ALTA |
| 2019 | Trend Micro: WannaCry ≈ 4x o resto do ransomware (detecções); 73.763 detecções de amostras com EternalBlue (baixa) | detecções | [Trend Micro](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/putting-the-eternal-in-eternalblue-mapping-the-use-of-the-infamous-exploit) | MÉDIA/BAIXA |
| 2019 | F-Secure: 556 mi de eventos SMB em honeypots (H1) | eventos em honeypots | [F-Secure](https://blog.f-secure.com/attack-landscape-h1-2019-iot-smb-traffic-abound) | BAIXA/MÉDIA |
| 2020 | ESET: WannaCryptor = 40,5% das detecções de ransomware (Q1); tentativas em ~50% do pico do Q2/2019; ~1 mi hosts SMBv1 (Shodan, 4/mai) | % de detecções; hosts expostos | [WeLiveSecurity](https://www.welivesecurity.com/2020/05/12/wannacryptor-remains-global-threat-three-years-on/) | ALTA (texto) |
| 2020 | Kaspersky WannaCry: 80.207 usuários únicos, 16% (1º) | usuários únicos | [Securelist](https://securelist.com/ransomware-by-the-numbers-reassessing-the-threats-global-impact/101965/) | ALTA |
| 2020 | CISA AA20-133A (mai): CVE-2017-0143 na lista 2016–2019 | ranking CISA | [CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-133a) | ALTA |
| 2020 | Rapid7 (mar): 500 mil–1,3 mi dispositivos SMB, ~343 mil SMBv1 sem auth | hosts expostos | [CybelAngel](https://cybelangel.com/blog/smbv1-still-a-threat/) | BAIXA |
| 2020 | Windows 7 ≈ 13,8% dos desktops (dez, StatCounter) | % de tráfego web | [TechRadar](https://www.techradar.com/pro/windows-11-market-share-slips-worryingly-as-windows-7-and-windows-10-record-growth-against-expectations) | BAIXA |
| 2021 | CVE-2017-0143 entra no KEV em 03/nov/2021 (ransomware: Known) | catálogo CISA | [KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | ALTA |
| 2021 | Demais métricas numéricas de EternalBlue | n/d | não encontrado | n/d |
| 2022 | CVE-2017-0144/0145 no KEV em 10/fev/2022 (prazo 10/ago); 0146 (25/mar), 0148 (6/abr), 0147 (24/mai) | catálogo CISA | [KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json); [CSO](https://www.csoonline.com/article/3649991/cisa-warns-about-15-actively-exploited-vulnerabilities.html) | ALTA |
| 2022 | Mondelez x Zurich: acordo (valor n/d); Merck ganha 1ª instância (reclamação US$ 1,4 bi) | processos | [The Record](https://therecord.media/merck-insurance-settlement-notpetya) | MÉDIA |
| 2023 | Kaspersky (Q1–Q3): EternalBlue/EternalRomance "continuam populares" (sem números); Merck vence em apelação | qualitativo | [Securelist Q3 2023](https://securelist.com/it-threat-evolution-q3-2023-non-mobile-statistics/111228/) | ALTA (texto) |
| 2024 | Merck x seguradoras: acordo confidencial; Kaspersky KSB 2024 sem menção a EternalBlue | qualitativo | [The Record](https://therecord.media/merck-insurance-settlement-notpetya); [Securelist KSB 2024](https://securelist.com/ksb-2024-statistics/114795/) | MÉDIA |
| 2025 | Windows 7 StatCounter: ~3,35–3,59% (ago) e 9,61% (set, anomalia) | % de tráfego web | [Windows Latest](https://windowslatest.com/2025/10/02/no-windows-7-isnt-gaining-market-share-in-2025) | BAIXA |
| 2026 | CVE-2017-0144 continua no KEV em 13/nov/2026 (ransomware: Known); nenhuma estatística de ataque achada | catálogo CISA | [KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | ALTA |

### Inferences
- A linha do tempo "pico em 2018–2019, queda em 2020, persistência residual 2021–2026" é sustentada por Kaspersky (2018), ESET (2019, 2020) e KEV (2021–2026), embora com métricas heterogêneas. Não misturar usuários únicos (Kaspersky) com detecções (ESET/Trend) no mesmo eixo.
- Recomendação para o grupo: usar gráficos separados (a) usuários únicos Kaspersky 2017–2020, (b) estimativas econômicas por evento com barras de faixa, (c) linha do tempo qualitativa do KEV.

### Gaps
- 2021–2026: não há contagens públicas de detecções de EternalBlue localizadas (Kaspersky, ESET, Check Point, Avast, Microsoft). Série contínua e comparável é inexistente nas fontes que consegui ler.

---

## Notas gerais para o redator

- **Limitações desta pesquisa:** ferramentas de busca retornaram resumos; várias páginas (Wired, Dark Reading, Reuters) foram bloqueadas; números marcados BAIXA/MÉDIA devem ser verificados na fonte antes de uso formal. O orçamento de chamadas foi superado para cobrir exposição, KEV e Brasil, mas mesmo assim ficaram lacunas listadas acima.
- **Fatos de contexto verificados:** Shadow Brokers vazou o EternalBlue em 14/abr/2017; Microsoft publicou o patch MS17-010 59 dias antes do surto de 12/mai/2017 (março/2017); SMBv1 foi depreciado pela Microsoft em 2013 (ESET). — [WeLiveSecurity 2020](https://www.welivesecurity.com/2020/05/12/wannacryptor-remains-global-threat-three-years-on/)
- **Fontes primárias que valem consulta direta adicional (não lidas por completo):** Check Point Cyber Attack Trends (relatórios mid-year 2018–2021, seção "Global Top Exploited Vulnerabilities"); Shadowserver dashboard (SMB); Rapid7 Project Sonar; CERT.br (estatísticas de incidentes e alertas); CISA AA21-209A, AA22-117A e avisos posteriores; Kaspersky Q2/2020–Q4/2022 (seção "Network attacks"); FedEx 10-K (FY2018) para o impacto da TNT.
