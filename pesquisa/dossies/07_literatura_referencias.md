# Literatura acadêmica e fontes autoritativas sobre EternalBlue / MS17-010 / WannaCry (bibliografia verificada, formato IEEE)

Data da pesquisa: 15/11/2026. Método de verificação: DOIs conferidos via API do Crossref (metadados de autores, venue, páginas) e OpenAlex (resumos); páginas web abertas por fetch direto (HTTP) ou WebFetch; resumos de artigos extraídos de resumos oficiais (arXiv/OpenAlex/Crossref) ou da própria página. Onde algo não pôde ser aberto, está marcado como **NÃO VERIFICADO** ou **VERIFICADO PARCIALMENTE**. Legenda de status: **[V]** = metadados e conteúdo conferidos; **[V-meta]** = existência/metadados conferidos (DOI/URL), mas resumo não obtido do original; **[V-sec]** = existe, mas o conteúdo foi conferido só em fonte secundária (resultado de busca); **[X]** = não usar.

---

## 1. Artigos acadêmicos (revisados por pares / preprints) sobre EternalBlue, MS17-010, SMBv1, WannaCry, detecção, propagação e ética de divulgação de vulnerabilidades

### Takeaway
A literatura acadêmica revisada por pares *específica* sobre EternalBlue é pequena (poucos trabalhos: Liu et al. 2022, Nguyen et al. 2024, Fujimoto et al. 2019, Le et al. 2025); o grosso é sobre WannaCry (ICACT 2018, JTIT 2019, ICMLA 2017, ISCC 2018). Para detecção por ML/IDS **não encontrei** artigo revisado por pares focado em tráfego EternalBlue (ver Gaps); as melhores âncoras são detecção por logs/assinaturas e análise comportamental. Para política de divulgação, as fontes sólidas são RAND (Ablon & Bogart, 2017), Belfer Center (Schwartz & Knake, 2016) e Wicker (CACM).

### Cited Findings

**A. Mecanismo do exploit / SMBv1**
- Liu, Chen, Zhang e Gao, "Working Mechanism of Eternalblue and Its Application in Ransomworm", capítulo LNCS (Springer, *Cyberspace Safety and Security*, 2022, pp. 178–191, DOI 10.1007/978-3-031-18067-5_13). Metadados conferidos no Crossref [V-meta]; o resumo vem da versão arXiv (2112.14773, só Zian Liu como autor): visão sistemática do EternalBlue (alto nível e código), engenharia reversa do código EternalBlue dentro do WannaCry e comparação com o módulo Metasploit; conclusão: o código permanece quase inalterado ao ser transplantado para o WannaCry, o que sugere viabilidade de detecção por assinatura — [Crossref](https://api.crossref.org/works/10.1007/978-3-031-18067-5_13); [arXiv 2112.14773](https://arxiv.org/abs/2112.14773)
- Le et al., "EternalBlue Exploit: Definitions and Working Mechanism", Springer (Algorithms for Intelligent Systems, 2025, pp. 1–13, DOI 10.1007/978-981-96-1452-3_1), 5 autores (Pham Le, Dang, Do, Hoang, Nguyen). Metadados conferidos [V-meta]; **resumo não obtido** (OpenAlex sem abstract) — não resumir além do título — [Crossref](https://api.crossref.org/works/10.1007/978-981-96-1452-3_1)
- Novokhrestov, Kalyakin, Kovalenko e Repkin, "Creating a vulnerable node based on the vulnerability MS17-010", arXiv:2401.14979 (jan/2024), **preprint, venue de publicação não confirmado**: descreve o princípio e a metodologia de exploração do MS17-010 (CVE-2017-0144, SMBv1), com representação formal em grafo MAL (Meta Attack Language) e script Python com Metasploit; fornece medidas básicas de segurança — [arXiv](https://arxiv.org/abs/2401.14979)
- Angeli, Aguiar, da Silva e Fontenelle, "Vulnerability exploitation in the SMBv1 protocol", 18th CONTECSI (Brasil; autores brasileiros). Apresenta a falha SMBv1 corrigida pelo MS17-010, exploração com EternalBlue/DoublePulsar e propagação via WannaCry em 12/05/2017; metodologia = pesquisa aplicada em estudo de campo; conclui que sistemas desatualizados continuam expostos — [DOI/Crossref](https://api.crossref.org/works/10.5748/18contecsi/pse/sec/6712), resumo via [OpenAlex](https://api.openalex.org/works/doi:10.5748/18contecsi/pse/sec/6712). Ano não consta no Crossref (a 18ª edição do CONTECSI, ao que sei, foi em 2021 — **inferido, confirmar**).

**B. Análise de WannaCry (estática/dinâmica/comportamental)**
- Hsiao e Kao, "The static analysis of WannaCry ransomware", ICACT 2018, pp. 153–158, DOI 10.23919/ICACT.2018.8323680 [V]: análise estática por engenharia reversa; descreve a anatomia multiestágio (deployment, instalação, destruição, C2) e mostra que o WannaCry integra as "hacking weapons" vazadas pelo Shadow Brokers — [OpenAlex](https://api.openalex.org/works/doi:10.23919/icact.2018.8323680). Nota: o Crossref tem DOIs duplicados (…8323679 e …8323680) para o mesmo título; usei …680, que traz páginas 153–158. O artigo "dynamic analysis" companheiro (Kao e Hsiao, DOI …8323681) consta com pp. 1–1 (aparentemente só resumo) — não recomendo citar.
- Akbanov, Vassilakis e Logothetis, "WannaCry Ransomware: Analysis of Infection, Persistence, Recovery Prevention and Propagation Mechanisms", *J. Telecommun. Inf. Technol.* (JTIT), n.º 1, pp. 113–124, 2019, DOI 10.26636/jtit.2019.130218 [V]: análise dinâmica em laboratório virtual dedicado; foca infecção, persistência, impedimento de recuperação e propagação, para apoiar o desenho de defesas — [OpenAlex](https://api.openalex.org/works/doi:10.26636/jtit.2019.130218); [DOI resolve para jtit.pl](https://doi.org/10.26636/jtit.2019.130218). (JTIT é periódico polonês do National Institute of Telecommunications; revisado por pares, mas de menor fator de impacto.)
- Chen e Bridges, "Automated Behavioral Analysis of Malware: A Case Study of WannaCry Ransomware", IEEE ICMLA 2017, pp. 454–460, DOI 10.1109/ICMLA.2017.0-119 [V]; também arXiv:1709.08753. Método para identificar e ranquear automaticamente as características mais discriminantes de ransomware a partir de logs de sistema (Cuckoo Sandbox) com WannaCry e duas amostras polimórficas; padrões permanecem precisos em cópias polimórficas do WannaCry nas quais 63 de 63 antivírus testados falham — [arXiv](https://arxiv.org/abs/1709.08753)
- Satheesh Kumar, Ben-Othman e Srinivasagan, "An Investigation on Wannacry Ransomware and its Detection", IEEE ISCC 2018, DOI 10.1109/ISCC.2018.8538354 [V]: análise estática e dinâmica; detecção por regras YARA com strings únicas decodificadas do arquivo WannaCry — [OpenAlex](https://api.openalex.org/works/doi:10.1109/iscc.2018.8538354)
- Chuquilla, Guarda e Ninahualpa Quiña, "Ransomware – WannaCry Security is everyone's", CISTI 2019 (Iberian Conf. on Information Systems and Technologies), DOI 10.23919/CISTI.2019.8760749 [V-meta]: artigo de conscientização/boas práticas, **pouco aprofundamento técnico** (baixa prioridade) — [OpenAlex](https://api.openalex.org/works/doi:10.23919/cisti.2019.8760749)
- Aljaidi et al., "NHS WannaCry Ransomware Attack: Technical Explanation of the Vulnerability, Exploitation, and Countermeasures", IEEE EICEEAI 2022, DOI 10.1109/EICEEAI56378.2022.10050485. **Metadados conferidos (7 autores), mas o resumo NÃO foi verificado**: o OpenAlex e a página do Heriot-Watt associam a este título um resumo de *outro* estudo (análise estatística de Hospital Episode Statistics, impacto de £5,9 mi) — resumo claramente trocado; **não usar o resumo, e citar com cautela** — [Crossref](https://api.crossref.org/works/10.1109/eiceeai56378.2022.10050485); [OpenAlex](https://api.openalex.org/works/doi:10.1109/eiceeai56378.2022.10050485)

**C. Propagação / modelagem de worm**
- Nguyen, Alain, Autrel, Bouabdallah, François e Doyen, "How Fast Does Malware Leveraging EternalBlue Propagate? The Case of WannaCry and NotPetya", IEEE NetSoft 2024, pp. 399–404, DOI 10.1109/NetSoft60951.2024.10588886 [V]: estudo empírico em rede local de 50 VMs; para o WannaCry, ~20% das infecções ocorrem em menos de 50 s e até 16 hosts são infectados em 100 s; compara estratégias de propagação (WannaCry só usa o exploit; NotPetya adiciona credenciais/PsExec/WMI) — [OpenAlex](https://api.openalex.org/works/doi:10.1109/netsoft60951.2024.10588886); [web search / Orbilu](https://orbilu.uni.lu/handle/10993/63286) (a página Orbilu deu erro de certificado SSL para meu cliente; a existência foi confirmada por Crossref e OpenAlex)
- Chernikova, Gozzi, Boboila, Perra, Eliassi-Rad e Oprea, "Modeling Self-Propagating Malware with Epidemiological Models", arXiv:2208.03276 (2022; **preprint**, não conferi publicação em periódico): analisa o modelo SIIDR; usa 15 traces de ataque WannaCry gerados em diversas condições; SIIDR se ajusta melhor aos dados que SI/SIS/SIR — [arXiv](https://arxiv.org/abs/2208.03276)

**D. Detecção (IDS / logs / datasets)**
- Fujimoto, Matsuda e Mitsunaga, "Detecting attacks leveraging vulnerabilities fixed in MS17-010 from Event Log", IEEE AINS 2019, pp. 42–47, DOI 10.1109/AINS47559.2019.8968703 [V]: propõe detectar ataques que exploram as falhas do MS17-010 (EternalBlue/EternalRomance) a partir dos Windows Event Logs nativos, útil onde IDS é difícil de implantar (ex.: ICS com sistemas sem patch) — [OpenAlex](https://api.openalex.org/works/doi:10.1109/ains47559.2019.8968703)
- Cordero et al., "On generating network traffic datasets with synthetic attacks for intrusion detection", arXiv:1905.00304 (2019): toolkit ID2T que injeta ataques sintéticos (incluindo o EternalBlue) no tráfego de fundo para avaliar IDS baseados em anomalia e assinatura — [arXiv](https://arxiv.org/abs/1905.00304). Tangencial (o EternalBlue é um dos ataques injetáveis, não o foco); venue final não conferido.
- Dillon e Davis (RiskSense), relatório técnico: mostram como simplificar o exploit para driblar regras de detecção então recomendadas por governos e fornecedores de antivírus — [PDF](https://dl.packetstormsecurity.net/papers/attack/EternalBlue_RiskSense_Analysis-1.2.pdf) (ver seção 3).

**E. Divulgação de vulnerabilidades / estocagem / ética**
- Ablon e Bogart, *Zero Days, Thousands of Nights: The Life and Times of Zero-Day Vulnerabilities and Their Exploits*, RAND Corporation, RR1751, 2017, DOI 10.7249/RR1751 (DOI verificado no Crossref; página da RAND responde HTTP 200). Pontos extraídos de resultados de busca que citam a RAND/Lawfare/Black Hat: amostra de ~200 zero-days de um vendedor do mercado cinza; vida média ≈ 6,9 anos (2.521 dias); ~25% não sobrevivem a 1,5 ano; quase 40% ainda desconhecidos publicamente; colisão anual de descobertas ~5,7% — **[V-sec] para os números** (a RAND bloqueou o WebFetch com 403; conferir direto no PDF antes de citar números) — [RAND](https://www.rand.org/pubs/research_reports/RR1751.html); [Lawfare](https://www.lawfaremedia.org/article/adding-data-vep-debate-rands-new-report); [slides Black Hat USA 2017 (PDF, HTTP 200)](https://www.blackhat.com/docs/us-17/thursday/us-17-Ablon-Bug-Collisions-Meet-Government-Vulnerability-Disclosure-Zero-Days-Thousands-Of-Nights-RAND.pdf)
- Schwartz e Knake, "Government's Role in Vulnerability Disclosure: Creating a Permanent and Accountable Vulnerability Equities Process", Belfer Center (Harvard Kennedy School), Discussion Paper 2016-04, jun/2016 (página HTTP 200). Argumenta que o VEP deve ser formalizado (ordem executiva), critérios públicos, relatório anual e supervisão; propõe vedar NDAs na compra de exploits — [Belfer Center](https://www.belfercenter.org/publication/governments-role-vulnerability-disclosure-creating-permanent-and-accountable); resumo conferido em [Schneier](https://www.schneier.com/blog/archives/2016/07/report_on_the_v.html) (via busca) — [V-sec] para as recomendações.
- Wicker, "The ethics of zero-day exploits…", *Commun. ACM*, vol. 64, n.º 1, pp. 97–103, 2021 (online dez/2020), DOI 10.1145/3393670 [V-meta]; subtítulo não conferido (o Crossref trunca o título); pergunta central (OpenAlex): servidores do governo dos EUA agem eticamente ao estocar vulnerabilidades? — [Crossref](https://api.crossref.org/works/10.1145/3393670)
- Vostoupal, "Stuxnet vs WannaCry and Albania: Cyber-attribution on trial", *Computer Law & Security Review*, vol. 54, art. 106008, set/2024, DOI 10.1016/j.clsr.2024.106008 [V-meta]; resumo não obtido; útil para atribuição jurídica — [Crossref](https://api.crossref.org/works/10.1016/j.clsr.2024.106008)
- Herr, "Development and Proliferation of Offensive Weapons in Cyber-Security", em *Cyber Weaponry* (Springer, 2018, pp. 125–141), DOI 10.1007/978-3-319-74107-9_10 [V-meta]; resumo não obtido (tangencial) — [Crossref](https://api.crossref.org/works/10.1007/978-3-319-74107-9_10)

**F. Casos e lições (secundário)**
- Adams, "Learning the lessons of WannaCry", *Computer Fraud & Security*, vol. 2018, n.º 9, pp. 6–9, DOI 10.1016/S1361-3723(18)30084-8 [V-meta]: artigo curto de revista profissional (resumo do OpenAlex: WannaCry trouxe atenção sem precedentes a ameaças de software malicioso que exigem resgate) — [OpenAlex](https://api.openalex.org/works/doi:10.1016/s1361-3723(18)30084-8)
- Trautman e Ormerod, "WannaCry, Ransomware, and the Emerging Threat to Corporations", SSRN, 2018, DOI 10.2139/ssrn.3238293 [V-meta]; resumo não obtido (direito corporativo/governança) — [Crossref](https://api.crossref.org/works/10.2139/ssrn.3238293)
- Moreira, Calegario, Duarte e dos Santos, "A era dos Crypto Ransomwares: um estudo de caso sobre o WannaCry", Anais do XVII SBSeg, Brasília, 2017, pp. 509–516, DOI 10.5753/sbseg.2017.19525 [V]: **único artigo brasileiro (SBC/SBSeg) encontrado sobre WannaCry**; artigo curto; resumo = estudo de caso para identificar oportunidades de melhoria em resposta a incidentes (a página não detalha resultados) — [SOL/SBC](https://sol.sbc.org.br/index.php/sbseg/article/view/19525); [Crossref](https://api.crossref.org/works/10.5753/sbseg.2017.19525). Observação: o autor (IME) etc. e o DOI resolvem via Crossref; a SOL e doi.org retornam 403 a clientes automatizados mas a página foi lida via WebFetch.

### Inferences
- Para um artigo de 4 páginas, o núcleo acadêmico mais defensável é: Liu et al. 2022 (mecanismo), Nguyen et al. 2024 (propagação), Akbanov et al. 2019 e Hsiao & Kao 2018 (análise de WannaCry), Fujimoto et al. 2019 (detecção), Moreira et al. 2017 (fonte brasileira SBSeg) e Ablon & Bogart / Schwartz & Knake (política).
- Como os melhores textos técnicos sobre o exploit são de pesquisa industrial (Check Point, RiskSense), vale citar ambos para o "como funciona" e usar os artigos revisados por pares para propagação/impacto/política.

### Gaps
- **Detecção por ML/IDS focada em tráfego EternalBlue**: não encontrei artigo revisado por pares verificável. Um resultado de busca mencionou um artigo da Lancaster (TNSM, "Practical Intrusion Detection of Emerging Threats") que usaria EternalRomance (não EternalBlue) e uma dissertação da ODU; **ambos não verificados** e não incluídos. O pesquisador deve fazer buscas no IEEE Xplore/ACM DL com "MS17-010 machine learning" / "SMB anomaly detection".
- Não encontrei artigo SBSeg/SBRC sobre EternalBlue/MS17-010 (só o de WannaCry de 2017). Um resultado de busca do SBSeg 2024 (UFMG/CERT.br, download 30037) tratava de varredura/Shodan e não confirmei relação com EternalBlue — descartado.
- Não encontrei artigos sobre "Vulnerability Equities Process" revisados por pares além de Wicker (CACM); Schwartz & Knake é relatório de think tank.
- Excluídos após verificação: (i) DOI 10.7717/peerj-cs.2130 (aparece em buscas Crossref como "EternalBlue…" via um registro *suplementar* mal indexado, mas o artigo principal é sobre ataques CONNECT em IoT-WSN, sem relação com EternalBlue — armadilha de citação); (ii) Boyanov, J. Scientific and Applied Research, 2018 (DOI 10.46687/jsar.v14i1.246): metadados existem, mas fonte obscura, conteúdo não verificado; (iii) Popli e Girdhar, "WannaCry Malware Analysis", MERI-Journal (2017): metadados existem, qualidade/revisão não verificadas.

---

## 2. Relatórios oficiais / governamentais (NAO, CISA, Casa Branca, Europol, CERT.br, GSI/CTIR Gov)

### Takeaway
As fontes oficiais mais fortes e verificadas: relatório do UK NAO (HC 414), revisão "Lessons learned" do NHS/DHSC (William Smart, fev/2018), alerta CISA TA17-132A (com atribuição à Coreia do Norte na revisão de jun/2018), boletim Microsoft MS17-010 (14/03/2017), registro NVD CVE-2017-0144 e comunicado da Casa Branca de 15/02/2018 sobre NotPetya. Europol e fontes brasileiras (CERT.br, CTIR Gov) não renderam um documento específico verificável sobre WannaCry/MS17-010.

### Cited Findings
- **NAO**, "Investigation: WannaCry cyber attack and the NHS", HC 414, sessão 2017–19, publicado em 27/10/2017 (data na página do NAO; o PDF fica em /2017/10/; fontes secundárias citam "25/04/2018" apenas como data da sessão/audiência da PAC — **a data correta é outubro de 2017, não 2018**). Achados: ao menos 81 dos 236 trusts da Inglaterra foram afetados; 603 outras organizações do NHS (incl. 595 clínicas de GPs) infectadas; 6.912 consultas canceladas registradas, estimativa >19.000 no total; cinco serviços de A&E desviaram pacientes; nenhuma organização pagou o resgate; o Departamento não sabe o custo; o NAO diz que o ataque foi relativamente pouco sofisticado e evitável com práticas básicas de segurança; Departamento foi alertado sobre riscos um ano antes e só respondeu formalmente em jul/2017 — [NAO (página)](https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/); [PDF](https://www.nao.org.uk/wp-content/uploads/2017/10/Investigation-WannaCry-cyber-attack-and-the-NHS.pdf) (HTTP 200)
- **W. Smart (CIO for Health and Social Care)**, "Lessons learned review of the WannaCry Ransomware Cyber Attack", NHS England/DHSC, 1/fev/2018, 42 páginas; revisão independente; conclui que o NHS não foi alvo específico; recomendações de preparação e resposta — [PDF](https://www.england.nhs.uk/wp-content/uploads/2018/02/lessons-learned-review-wannacry-ransomware-cyber-attack-cio-review.pdf) (cabeçalho e sumário lidos localmente)
- **CISA/US-CERT TA17-132A**, "Indicators Associated With WannaCry Ransomware": lançado em 12/05/2017, revisado em 07/06/2018; o dropper se propaga explorando MS17-010/EternalBlue em SMBv1; patch da Microsoft em 14/03/2017 (e para XP/Windows 8/Server 2003 em 13/05/2017); recomenda aplicar o patch, desativar SMBv1 e bloquear SMB (TCP 445, UDP 137–138, TCP 139) nas bordas; a revisão de 2018 atribui a variante WannaCry ao governo norte-coreano — [CISA](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware) (lido via WebFetch; **retorna 403 a clientes curl/Python, mas abre em navegador**)
- **CISA/US-CERT**, "Microsoft SMBv1 Vulnerability" (alerta de 16/03/2017, arquivado): exorta a revisar o boletim MS17-010 e aplicar a atualização; aponta remoção do SMBv1 — [CISA](https://www.cisa.gov/news-events/alerts/2017/03/16/microsoft-smbv1-vulnerability)
- **Microsoft Security Bulletin MS17-010** (4013389), publicado em 14/03/2017: corrige vulnerabilidades de execução remota de código no servidor SMBv1 (CVE-2017-0143, -0144, -0145, -0146, -0148; -0147 é divulgação de informação); "mitigating factors: nenhum"; workaround = desativar SMBv1 — [Microsoft Learn](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- **NVD CVE-2017-0144** ("Windows SMB Remote Code Execution Vulnerability"): publicado em 17/03/2017; CVSS v3.1 = 8,8 (High), vetor AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H; CVSS v2 = 9,3; incluído no catálogo KEV da CISA em 10/02/2022 ("Microsoft SMBv1 Remote Code Execution Vulnerability"); registro modificado pela última vez em 14/08/2026 — consultado na [API do NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0144) (a página [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) é renderizada por JavaScript).
- **Casa Branca**, "Statement from the Press Secretary", 15/02/2018: atribui o ataque NotPetya (jun/2017) aos militares russos, descreve-o como dos ataques cibernéticos mais destrutivos e custosos; chamou-o de imprudente e indiscriminado e prometeu "consequências internacionais" — [Archive Casa Branca](https://trumpwhitehouse.archives.gov/briefings-statements/statement-press-secretary-25/). (O texto da página foi parafraseado via WebFetch.) Observação: NotPetya também usou EternalBlue/EternalRomance conforme [Cisco Talos](https://blog.talosintelligence.com/worldwide-ransomware-variant/).
- **Europol**: a manchete "Cyber-attack: Europol says it was unprecedented in scale" (BBC, mai/2017) cita >200.000 vítimas em ≥150 países (Rob Wainwright) — apenas fonte secundária via busca ([BBC](https://bbc.in/3uNaw13), não aberto). A página do IOCTA 2017 do Europol existe (HTTP 200) mas o corpo não foi carregado, então **não foi possível confirmar menção ao WannaCry**; a URL de press release que tentei retornou 404 — [Europol IOCTA 2017](https://www.europol.europa.eu/publications-events/main-reports/internet-organised-crime-threat-assessment-iocta-2017)
- **Brasil – CERT.br**: o site cert.br abre (WebFetch), mas a página inicial não menciona WannaCry/MS17-010/SMB; existe link para guia "Ransomware" em `/docs/ransomware/` (não aberto). Meu cliente Python/curl falha na verificação do certificado TLS do cert.br — [CERT.br](https://www.cert.br/). Uma apresentação do CERT.br (CEMIG 2017) aparece nas buscas listando o WannaCry como episódio de mai/2017 — [PDF](https://www.cert.br/palestras/certbr-cemig2017.pdf) (**apenas snippet de busca, não aberto**).
- **Brasil – GSI/CTIR Gov**: encontrei, por busca, o "Alerta nº 04/2017 – Ataques de Ransomware Petrwrap/Petya" (27/06/2017), que recomenda isolar redes, aplicar MS17-010 e bloquear UDP 137/138 e TCP 139/445 — mas a URL do PDF retorna uma página "Estamos em manutenção" quando acessada diretamente; **conteúdo NÃO VERIFICADO**. Não achei alerta específico sobre WannaCry — [URL do PDF](https://www.gov.br/ctir/pt-br/centrais-de-conteudo/publicacoes/alertas/2017/alerta_2017_04_ransomwarepetrwrap.pdf)

### Inferences
- A frase "UK National Audit Office (2018)" no enunciado deve ser corrigida para 2017 (NAO, 27/out/2017); a citação IEEE deve usar a data da página do NAO.
- Para a seção brasileira, a fonte confiável hoje é o SBSeg 2017 (Moreira et al.); CERT.br/CTIR Gov servem como contexto, mas o grupo precisaria abrir manualmente os PDFs antes de citar.

### Gaps
- Não encontrei **nota/aviso do CERT.br** específico sobre WannaCry nem alerta do CTIR Gov sobre WannaCry (só Petya).
- **CERT/CC**: o endereço que eu tinha em mente (VU#867968) **não é sobre MS17-010** — é sobre um DoS no SMB2 Tree Connect (CVE-2017-0016, MS17-012). Não achei nota do CERT/CC sobre MS17-010. Não usar.
- Atribuição formal de WannaCry (Casa Branca/dez-2017, NCSC UK, DOJ/Park Jin Hyok set-2018): as URLs que tentei (NCSC) retornaram 404 ou (DOJ) conteúdo vazio; só a revisão de 2018 do CISA TA17-132A foi verificada para atribuição.
- Press release original do Europol não verificado.

---

## 3. Relatórios técnicos de indústria (Check Point, Microsoft, Kaspersky, Symantec, Cisco Talos, zerosum0x0/RiskSense, MalwareTech, Rapid7, Trend Micro, Virus Bulletin)

### Takeaway
Os write-ups industriais mais citáveis e verificados: Check Point Research (Grossman, 29/09/2017) para a anatomia do exploit; RiskSense (Dillon & Davis, 05/06/2017) para port Windows 10 e evasão de assinaturas; Cisco Talos (WannaCry 12/05/2017 e Nyetya 27/06/2017); Microsoft MMPC (12/05/2017); Kaspersky GReAT; zerosum0x0 (DoublePulsar). MalwareTech não pôde ser aberto por bot (403).

### Cited Findings
- **Check Point Research, N. Grossman, "EternalBlue – Everything There Is To Know"** (29/09/2017): três bugs em `srv.sys`: (A) *Wrong Casting* — `SrvOs2FeaListSizeToNT` atualiza só a word baixa de um valor de 32 bits, fazendo o tamanho crescer em vez de encolher e causando escrita fora do buffer do non-paged pool; (B) *Wrong Parsing Function* — `SMB_COM_NT_TRANSACT` usa campo de comprimento de 32 bits e `SMB_COM_TRANSACTION2` usa 16 bits; (C) *Non-paged Pool Allocation* — via `BlockingSessionSetupAndX`/`GetNtSecurityParameters`, permite heap grooming controlado; a cadeia sobrescreve estruturas `srvnet` apontando para heap executável do HAL (pré-Windows 8) e executa shellcode (DoublePulsar) — [Check Point](https://research.checkpoint.com/2017/eternalblue-everything-know/)
- **Check Point Research, "Brokers in the Shadows"** (25/05/2017): Shadow Brokers publicaram os tools em 14/04/2017 ("Lost in Translation"); antes do WannaCry, >400.000 computadores em ~150 países teriam sido infectados com o backdoor DoublePulsar; cadeia reconhecimento → exploração (EternalBlue etc.) → backdoor; EternalBlue = CVE-2017-0144, estouro de buffer — [Check Point](https://research.checkpoint.com/2017/brokers-shadows-analyzing-vulnerabilities-attacks-spawned-leaked-nsa-hacking-tools/)
- **RiskSense (S. Dillon "zerosum0x0" e D. Davis), "EternalBlue: Exploit Analysis and Port to Microsoft Windows 10"**, v1.2, 05/06/2017: exploit descrito como uma das mais complexas já escritas; a falha vem de registradores de tamanho errado; o FUZZBUNCH traz bypass de ASLR e o port para Windows 10 precisou de bypass de DEP; mostram como reduzir o exploit para driblar regras de detecção recomendadas por governos/AV — lido do PDF localmente ([PDF, espelho Packet Storm](https://dl.packetstormsecurity.net/papers/attack/EternalBlue_RiskSense_Analysis-1.2.pdf)); autores confirmados na seção "Authors" do PDF. Não conferi o host original da RiskSense.
- **Cisco Talos (M. Lee, W. Mercer, P. Rascagneres, C. Williams), "Player 3 Has Entered the Game: Say Hello to 'WannaCry'"** (12/05/2017): usa ETERNALBLUE (MS17-010, TCP 445) e instala DoublePulsar para executar o ransomware; varredura da sub-rede local e de IPs aleatórios; kill switch = HTTP GET para domínio; se a requisição funciona o malware encerra; domínio registrado em 12/05/2017 em um sinkhole — [Talos](https://blog.talosintelligence.com/wannacry/)
- **Cisco Talos, "New Ransomware Variant 'Nyetya' Compromises Systems Worldwide"** (27/06/2017, atualizado 06/07/2017): amostra "leverages EternalBlue, EternalRomance, WMI, and PsExec" para movimento lateral; vetor inicial associado a atualizações do software contábil MeDoc (não confirmado à época) — [Talos](https://blog.talosintelligence.com/worldwide-ransomware-variant/)
- **Microsoft Defender/MMPC, "WannaCrypt ransomware worm targets out-of-date systems"** (12/05/2017): o worm usou código público do exploit "EternalBlue" (a postagem identifica **CVE-2017-0145**), corrigido pelo MS17-010; cria serviço `mssecsvc2.0`; varre IPs aleatórios; Windows 10 não foi afetado; mitigação: aplicar MS17-010, desabilitar SMBv1, bloquear 445 — [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/). **Discrepância**: NVD/Check Point mapeiam EternalBlue a CVE-2017-0144; Microsoft nesse post cita 0145; outra fonte cita 0143 — o grupo deve escolher CVE-2017-0144 (NVD/CISA KEV) e anotar que há variação entre fontes.
- **Microsoft MSRC, "Customer Guidance for WannaCrypt attacks"** (12/05/2017): orienta aplicar MS17-010 e desabilitar SMBv1; Windows Defender passou a detectar como Ransom:Win32/WannaCrypt — [MSRC](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks) (URL HTTP 200; **conteúdo só via snippets de busca, não lido integralmente**)
- **Microsoft (Brad Smith), "The need for urgent collective action to keep people safe online: Lessons from last week's cyberattack"** (14/05/2017): critica a estocagem de vulnerabilidades por governos, compara exploits vazados a armas militares roubadas e propõe uma "Digital Geneva Convention" exigindo que governos reportem vulnerabilidades aos fornecedores — [Microsoft On the Issues](https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/). A autoria (Brad Smith, presidente da Microsoft) **não aparece no texto retornado pelo fetch** — confirmar na página.
- **Kaspersky GReAT, "WannaCry ransomware used in widespread attacks all over the world"** (12/05/2017): >45.000 ataques em 74 países vistos pelos produtos Kaspersky; EternalBlue vazado pelo Shadow Brokers em 14/04/2017; MS17-010 corrigido em março. **Erro na própria postagem**: descreve o protocolo como SMBv2, e comentaristas apontam que MS17-010 trata do SMBv1 — [Securelist](https://securelist.com/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/78351/). Também verificada: [Wannacry and Lazarus Group – the missing link?](https://securelist.com/wannacry-and-lazarus-group-the-missing-link/78431/) (HTTP 200, conteúdo não lido).
- **Symantec Security Response, "What you need to know about the WannaCry Ransomware"**: propagação por vulnerabilidades corrigidas no MS17-010; EternalBlue lançado pelos Shadow Brokers em abr/2017; vetor da primeira infecção em uma organização permanece não confirmado; recomenda instalar MS17-010 — [Security.com/Symantec](https://symantec-enterprise-blogs.security.com/threatintelligence/wannacry-ransomware-attack). O post "WannaCry: Ransomware attacks show strong links to Lazarus group" (22/05/2017) existe segundo [CyberScoop/Help Net Security](https://www.helpnetsecurity.com/2017/05/23/wannacry-lazarus-links/) mas **sua URL original retorna 404** — não citar a URL antiga; atribuição foi contestada por críticos.
- **zerosum0x0 (S. Dillon), "DoublePulsar Initial SMB Backdoor Ring 0 Shellcode Analysis"** (21/04/2017): analisa o shellcode entregue via EternalBlue em Windows Server 2008 R2 SP1 x64; instala hook na `SrvTransaction2DispatchTable`; comandos via Trans2 (ping, exec, kill) — [blog](https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html)
- **Rapid7 (boB Rudis), "Wanna Decryptor (WNCRY) Ransomware Explained"** (12/05/2017; atualizado 07/09/2024): chama o WannaCry de "ransomworm"; explora falha de execução remota no SMB (patch MS17-010 de 14/03/2017); Project Sonar encontrou >1,8 milhão de dispositivos respondendo a SMB — [Rapid7](https://www.rapid7.com/blog/post/2017/05/12/wanna-decryptor-wncry-ransomware-explained/). Complemento: [Rapid7 – EternalBlue: Metasploit Module for MS17-010](https://www.rapid7.com/blog/post/2017/05/20/metasploit-the-power-of-the-community-and-eternalblue/) (HTTP 200, 20/05/2017, conteúdo não lido).
- **Virus Bulletin, "EternalBlue: a prominent threat actor of 2017–2018"** (jun/2018): paper de Kulkarni, Patil, Kadam e Dolas (Quick Heal/Seqrite Security Labs, Índia); o EternalBlue usa três bugs SMB mais bypass de ASLR — a página abre (HTTP 200) mas o texto retornou 403 ao WebFetch; autoria e resumo vêm de resultados de busca/[blog VB](https://virusbulletin.com/blog/2018/06/paper-eternalblue-prominent-threat-actor-20172018) — **[V-sec]** — [VB](https://www.virusbulletin.com/virusbulletin/2018/06/eternalblue-prominent-threat-actor-20172018/)
- **MalwareTech (M. Hutchins), "How to Accidentally Stop a Global Cyber Attacks"** (13/05/2017): o domínio não registrado no malware foi registrado, interrompendo a propagação; ele próprio depois acreditou que o domínio era uma ferramenta de anti-análise e não um kill switch deliberado (segundo cobertura da imprensa). **O site responde 403 a clientes automatizados; conteúdo NÃO lido diretamente — apenas snippets de busca e imprensa** — [post](https://malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html); [Dark Reading sobre o debate do kill switch](https://www.darkreading.com/threat-intelligence/wannacry-s-kill-switch-may-have-been-a-sandbox-evasion-tool)
- **Trend Micro**: "Massive WannaCry/Wcry Ransomware Attack Hits Various Countries" (mai/2017) — [EN](https://www.trendmicro.com/en_us/research/17/e/massive-wannacrywcry-ransomware-attack-hits-various-countries.html) (HTTP 200; versão pt_BR também 200); "「WannaCry」を拡散させた脆弱性攻撃「EternalBlue」の仕組みを解説" (em japonês; mecanismo de EternalBlue) — [JP](https://www.trendmicro.com/ja_jp/research/17/f/mechanism-of-eternalblue-the-vulnerability-attack-that-spread-wannacry.html) (HTTP 200). A versão em inglês dessa URL deu 404.
- **Kryptos Logic, "WannaCry: Two Weeks and 16 Million Averted Ransoms Later"** — [blog](https://www.kryptoslogic.com/blog/2017/05/wannacry-two-weeks-and-16-million-averted-ransoms-later/) (HTTP 200; conteúdo não lido; só título confere).

### Inferences
- Entre as fontes industriais, Check Point, RiskSense e Talos têm autoria clara, data e profundidade técnica suficientes para 4 páginas IEEE. Kaspersky e Microsoft são úteis para cronologia e mitigação, com ressalvas (SMBv2 vs SMBv1; CVE 0145 vs 0144).
- Atribuição à Coreia do Norte (Symantec/CISA) é assunto sensível: citar a CISA como fonte primária e tratar o post da Symantec como evidência técnica, não como veredito.

### Gaps
- MalwareTech: conteúdo original não lido. Symantec "strong links to Lazarus": URL original quebrada. Virus Bulletin: texto completo não lido por mim. MSRC "Customer Guidance": página não lida integralmente.
- Não busquei o Rapid7 "WannaCry Update: Vulnerable SMB Shares" (apenas URL checada) nem o Black Hat 2017 "EternalBlue" (não encontrei palestra Black Hat sobre EternalBlue em si).

---

## 4. Livros e palestras (Greenberg, Perlroth, Black Hat / DEF CON)

### Takeaway
Livros existem e foram confirmados quanto a título/autor/editora/ISBN via Open Library, mas **não verifiquei os capítulos** que tratam do EternalBlue/NotPetya/Shadow Brokers. As palestras verificadas: DEF CON 26 (zerosum0x0) sobre MS17-010 e Black Hat USA 2017 (Ablon & Bogart/RAND) sobre estocagem de zero-days.

### Cited Findings
- A. Greenberg, *Sandworm* — Doubleday, 2019 (Open Library: autor Andy Greenberg, 1.ª publicação 2019, editora Doubleday/Knopf Doubleday, ISBN 0385544405 listado) — [Open Library](https://openlibrary.org/search.json?q=Sandworm+Greenberg). Subtítulo não confirmado na consulta (de memória: "A New Era of Cyberwar and the Hunt for the Kremlin's Most Dangerous Hackers" — confirmar na capa). Relevância ao tema (NotPetya e EternalBlue) é do meu conhecimento prévio, **não verificada nesta sessão**.
- N. Perlroth, *This Is How They Tell Me the World Ends* — Bloomsbury, 2021 (Open Library: Bloomsbury Publishing, 2021, ISBN 9781635576054) — [Open Library](https://openlibrary.org/search.json?q=This+Is+How+They+Tell+Me+the+World+Ends). Subtítulo/capítulos não verificados; relevância (mercado de zero-days, Shadow Brokers) vem de conhecimento prévio.
- S. Dillon (zerosum0x0), "Demystifying MS17-010: Reverse Engineering the ETERNAL Exploits", **DEF CON 26**, 12/08/2018 (45 min): explica os exploits ETERNALBLUE/CHAMPION/ROMANCE/SYNERGY, internos do Windows e como o patch MS17-010 os corrigiu; vídeo no YouTube e Infocon; a página não lista slides — [InfoconDB](https://infocondb.org/con/def-con/def-con-26/demystifying-ms17-010-reverse-engineering-the-eternal-exploits)
- L. Ablon e A. Bogart, "Bug Collisions Meet Government Vulnerability Disclosure (Zero Days, Thousands of Nights)", **Black Hat USA 2017** (slides PDF HTTP 200) — [PDF](https://www.blackhat.com/docs/us-17/thursday/us-17-Ablon-Bug-Collisions-Meet-Government-Vulnerability-Disclosure-Zero-Days-Thousands-Of-Nights-RAND.pdf); listagem em [InfoconDB](https://infocondb.org/con/black-hat/black-hat-usa-2017/zero-days-thousands-of-nights-the-life-and-times-of-zero-day-vulnerabilities-and-their-exploits)

### Inferences
- Se os livros forem usados, citar apenas após abrir o livro (número de página/capítulo) — as notas de rodapé de um artigo de 4 páginas raramente comportam isso; prefira RAND + NAO + Microsoft (B. Smith) para a discussão ética.

### Gaps
- Nenhuma palestra Black Hat específica sobre EternalBlue encontrada (só a da RAND). Não verifiquei capítulos/páginas dos livros.

---

## 5. Sites recomendados pelo professor — existem páginas sobre EternalBlue / MS17-010 / WannaCry?

### Takeaway
Quase todos os sites têm página sobre WannaCry e/ou EternalBlue, com exceção de malwiki.org (domínio redireciona para site não relacionado — **não usar**) e CERT/CC (sem nota sobre MS17-010 encontrada). Vários sites bloqueiam clientes automatizados com 403 mas as páginas existem (confirmadas via WebFetch/busca).

### Cited Findings (URL, status, observação)
| Site | URL | Resultado | Observação |
|---|---|---|---|
| malwiki.org | https://malwiki.org/ | **403 (curl)**; WebFetch relatou **redirecionamento 301 para `mufasatotoamanah.com`** (domínio sem relação aparente com malware; não abri) | **Não usar**. Nenhuma página de EternalBlue/WannaCry encontrada. Possivelmente domínio expirado/sequestrado ou outro site pretendido; confirmar com o professor. |
| Malpedia (Fraunhofer FKIE) | https://malpedia.caad.fkie.fraunhofer.de/ | Home abre via WebFetch; `/details/win.wannacry` retornou **404** no WebFetch; Python falha no certificado TLS | Página de família WannaCry **NÃO confirmada**; o professor pode ter outro caminho. |
| Trend Micro Research | [Massive WannaCry/Wcry…](https://www.trendmicro.com/en_us/research/17/e/massive-wannacrywcry-ransomware-attack-hits-various-countries.html); [mecanismo EternalBlue (JP)](https://www.trendmicro.com/ja_jp/research/17/f/mechanism-of-eternalblue-the-vulnerability-attack-that-spread-wannacry.html) | 200 / 200 | Páginas `vinfo/…/eternalblue` e `…ransom.win32.wannacry.a` redirecionam para índices genéricos (não confirmadas). |
| Kaspersky | [Resource Center – WannaCry](https://www.kaspersky.com/resource-center/threats/ransomware-wannacry); [KLA10977](https://threats.kaspersky.com/en/vulnerability/KLA10977/); [Intrusion.Win.MS17-010](https://threats.kaspersky.com/en/threat/Intrusion.Win.MS17-010/); Securelist (ver seção 3) | 200 | O Resource Center cita EternalBlue mas não nomeia MS17-010 nem SMB. A URL `…/definitions/what-is-eternalblue` redireciona ao índice (página dedicada **não confirmada**). `encyclopedia.kaspersky.com/glossary/eternalblue/` = 404. |
| Avast (Avast Academy "c-" pages) | https://www.avast.com/c-eternalblue ; https://www.avast.com/c-wannacry | 200 (curl), títulos "EternalBlue Exploit \| MS17-010 Explained" e "WannaCry Ransomware Attack: What is it?"; WebFetch 403 | Conteúdo não lido; existem. |
| Malwarebytes / ThreatDown | [WannaCry](https://www.malwarebytes.com/wannacry); [Glossário EternalBlue](https://www.malwarebytes.com/glossary/eternalblue); [Labs "The worm that spreads WanaCrypt0r"](https://www.malwarebytes.com/blog/news/2017/05/the-worm-that-spreads-wanacrypt0r); [ThreatDown "How did the WannaCry ransomworm spread?"](https://www.threatdown.com/blog/how-did-the-wannacry-ransomworm-spread/) | 200 | Glossário: EternalBlue é uma das ferramentas vazadas pelo Shadow Brokers que exploram a implementação SMB do Windows; WannaCry e NotPetya a usaram (lido). Labs e ThreatDown: só título/trechos de busca. |
| Imperva | [What is WannaCry](https://www.imperva.com/learn/application-security/wannacry-ransomware/) | 200 (lido) | Explica worm via SMB, EternalBlue (atribuído à NSA, vazado pelo Shadow Brokers) e MS17-010. `…/eternalblue/` = 404. |
| Cloudflare Learning | [What was the WannaCry ransomware attack?](https://www.cloudflare.com/learning/security/ransomware/wannacry-ransomware/) | 200 via `workers.cloudflare.com` → redireciona; `www` direto dá 403 a bots | Conteúdo (via snippet de busca): ataque de 12/05/2017, >200.000 computadores em >150 países; patch de 14/03; dá destaque ao produto Cloudflare One (cunho comercial). |
| CISA | [TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware); [SMBv1 alert](https://www.cisa.gov/news-events/alerts/2017/03/16/microsoft-smbv1-vulnerability) | Lidos via WebFetch (403 a curl) | Fonte primária; ver seção 2. KEV: CVE-2017-0144 incluído em 10/02/2022 (via NVD). |
| NVD | [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) | 200 (página JS); dados lidos pela API | Ver seção 2. |
| CERT/CC Vulnerability Notes | — | **Nota sobre MS17-010 não encontrada**; VU#867968 é outra falha (MS17-012) | Não usar VU#867968. |
| Symantec/Broadcom | [What you need to know about the WannaCry Ransomware](https://symantec-enterprise-blogs.security.com/threatintelligence/wannacry-ransomware-attack) | 200 (lido) | `symantec.com/security-center/writeup/…` redireciona para índice Broadcom (**não confirmado**). |
| Microsoft Digital Defense Report | [MDDR 2024](https://www.microsoft.com/en-us/security/security-insider/intelligence-reports/microsoft-digital-defense-report-2024) | 200 (redireciona para a página de threat landscape) | Relatório anual geral (existe desde 2020); **não verifiquei menção a EternalBlue/WannaCry** — improvável como referência específica. |
| Check Point Research | [EternalBlue](https://research.checkpoint.com/2017/eternalblue-everything-know/); [Brokers in the Shadows](https://research.checkpoint.com/2017/brokers-shadows-analyzing-vulnerabilities-attacks-spawned-leaked-nsa-hacking-tools/) | 200 (lidos) | Ver seção 3. Há também uma página de hub sobre WannaCry no checkpoint.com (HTTP 202, conteúdo não lido). |
| CrowdStrike | [CrowdStrike Falcon Prevents WannaCry Ransomware](https://www.crowdstrike.com/en-us/blog/falcon-endpoint-protection-blocks-the-ransomware-that-attacked-the-nhs/) | 200 (lido) | 12/05/2017 (atualizado 14/05): cita EternalBlue e MS17-010; **cunho de produto** (Falcon). Páginas "cybersecurity-101/wannacry" que tentei deram 404. |

### Inferences
- Como "referências básicas" do professor, as páginas mais substantivas e estáveis são: Malwarebytes glossário, Imperva, Kaspersky Resource Center (WannaCry), Trend Micro Research, Check Point Research e CISA. Cloudflare/CrowdStrike têm viés comercial (apresentam produto).

### Gaps
- Malpedia (página da família), malwiki.org (qual é o site correto), Trend Micro `vinfo` e Kaspersky `what-is-eternalblue`: não confirmados. Conteúdo de Avast e Cloudflare não lido integralmente.

---

## 6. Lista final pronta para colar (IEEE, ordenada por relevância; 30 referências)

### Takeaway
30 referências com metadados conferidos. Acessos conferidos em 15/11/2026 → usei "Accessed: Nov. 15, 2026" nas fontes web (o grupo deve trocar pela própria data de acesso). Itens marcados com (⚠) têm ressalva descrita na coluna de notas abaixo da lista.

### Cited Findings (lista numerada)

[1] N. Grossman, "EternalBlue – Everything there is to know," Check Point Research, Sep. 29, 2017. [Online]. Available: https://research.checkpoint.com/2017/eternalblue-everything-know/ (Accessed: Nov. 15, 2026).

[2] Z. Liu, C. Chen, L. Y. Zhang, and S. Gao, "Working mechanism of EternalBlue and its application in ransomworm," in *Cyberspace Safety and Security (CSS 2022)* (Lecture Notes in Computer Science). Cham, Switzerland: Springer, 2022, pp. 178–191, doi: 10.1007/978-3-031-18067-5_13. (Preprint: arXiv:2112.14773.)

[3] S. Dillon and D. Davis, "EternalBlue: Exploit analysis and port to Microsoft Windows 10," RiskSense Threat Research, Ver. 1.2, Jun. 5, 2017. [Online]. Available: https://dl.packetstormsecurity.net/papers/attack/EternalBlue_RiskSense_Analysis-1.2.pdf (Accessed: Nov. 15, 2026). (⚠ espelho Packet Storm)

[4] Microsoft, "Microsoft Security Bulletin MS17-010 – Critical: Security update for Microsoft Windows SMB Server (4013389)," Mar. 14, 2017. [Online]. Available: https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010 (Accessed: Nov. 15, 2026).

[5] NIST National Vulnerability Database, "CVE-2017-0144 detail," published Mar. 17, 2017. [Online]. Available: https://nvd.nist.gov/vuln/detail/CVE-2017-0144 (Accessed: Nov. 15, 2026).

[6] D. D. A. Nguyen, P. Alain, F. Autrel, A. Bouabdallah, J. François, and G. Doyen, "How fast does malware leveraging EternalBlue propagate? The case of WannaCry and NotPetya," in *Proc. 2024 IEEE 10th Int. Conf. Netw. Softwarization (NetSoft)*, Jun. 2024, pp. 399–404, doi: 10.1109/NetSoft60951.2024.10588886.

[7] M. Akbanov, V. G. Vassilakis, and M. D. Logothetis, "WannaCry ransomware: Analysis of infection, persistence, recovery prevention and propagation mechanisms," *J. Telecommun. Inf. Technol.*, no. 1, pp. 113–124, Mar. 2019, doi: 10.26636/jtit.2019.130218.

[8] S.-C. Hsiao and D.-Y. Kao, "The static analysis of WannaCry ransomware," in *Proc. 20th Int. Conf. Adv. Commun. Technol. (ICACT)*, Feb. 2018, pp. 153–158, doi: 10.23919/ICACT.2018.8323680.

[9] Q. Chen and R. A. Bridges, "Automated behavioral analysis of malware: A case study of WannaCry ransomware," in *Proc. 16th IEEE Int. Conf. Mach. Learn. Appl. (ICMLA)*, Dec. 2017, pp. 454–460, doi: 10.1109/ICMLA.2017.0-119.

[10] G. B. Moreira, V. M. Calegario, J. C. Duarte, and A. F. P. dos Santos, "A era dos crypto ransomwares: um estudo de caso sobre o WannaCry," in *Anais do XVII Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (SBSeg)*, Brasília, Brazil, 2017, pp. 509–516, doi: 10.5753/sbseg.2017.19525.

[11] M. Fujimoto, W. Matsuda, and T. Mitsunaga, "Detecting attacks leveraging vulnerabilities fixed in MS17-010 from event log," in *Proc. 2019 IEEE Conf. Appl., Inf. Netw. Secur. (AINS)*, Nov. 2019, pp. 42–47, doi: 10.1109/AINS47559.2019.8968703.

[12] M. Satheesh Kumar, J. Ben-Othman, and K. G. Srinivasagan, "An investigation on WannaCry ransomware and its detection," in *Proc. 2018 IEEE Symp. Comput. Commun. (ISCC)*, Jun. 2018, doi: 10.1109/ISCC.2018.8538354. (⚠ páginas não confirmadas)

[13] A. B. Angeli, W. S. Aguiar, D. C. da Silva, and J. M. B. Fontenelle, "Vulnerability exploitation in the SMBv1 protocol," in *Proc. 18th CONTECSI Int. Conf. Inf. Syst. Technol. Manage.*, São Paulo, Brazil, [year to confirm], doi: 10.5748/18contecsi/pse/sec/6712. (⚠ ano/local não confirmados)

[14] M. Lee, W. Mercer, P. Rascagneres, and C. Williams, "Player 3 has entered the game: Say hello to 'WannaCry'," Cisco Talos Intelligence Group, May 12, 2017. [Online]. Available: https://blog.talosintelligence.com/wannacry/ (Accessed: Nov. 15, 2026).

[15] Microsoft Defender Security Research Team, "WannaCrypt ransomware worm targets out-of-date systems," Microsoft Security Blog, May 12, 2017. [Online]. Available: https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/ (Accessed: Nov. 15, 2026). (⚠ cita CVE-2017-0145)

[16] Kaspersky GReAT, "WannaCry ransomware used in widespread attacks all over the world," Securelist, May 12, 2017. [Online]. Available: https://securelist.com/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/78351/ (Accessed: Nov. 15, 2026). (⚠ chama o protocolo de SMBv2)

[17] Check Point Research, "Brokers in the shadows: Analyzing vulnerabilities and attacks spawned by the leaked NSA hacking tools," May 25, 2017. [Online]. Available: https://research.checkpoint.com/2017/brokers-shadows-analyzing-vulnerabilities-attacks-spawned-leaked-nsa-hacking-tools/ (Accessed: Nov. 15, 2026).

[18] Cisco Talos, "New ransomware variant 'Nyetya' compromises systems worldwide," Jun. 27, 2017 (updated Jul. 6, 2017). [Online]. Available: https://blog.talosintelligence.com/worldwide-ransomware-variant/ (Accessed: Nov. 15, 2026).

[19] zerosum0x0 (S. Dillon), "DoublePulsar initial SMB backdoor ring 0 shellcode analysis," Apr. 21, 2017. [Online]. Available: https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html (Accessed: Nov. 15, 2026).

[20] P. Kulkarni, S. Patil, P. Kadam, and A. Dolas, "EternalBlue: A prominent threat actor of 2017–2018," Virus Bulletin, Jun. 2018. [Online]. Available: https://www.virusbulletin.com/virusbulletin/2018/06/eternalblue-prominent-threat-actor-20172018/ (Accessed: Nov. 15, 2026). (⚠ autoria via busca; texto não lido)

[21] US-CERT/CISA, "Alert (TA17-132A): Indicators associated with WannaCry ransomware," May 12, 2017; rev. Jun. 7, 2018. [Online]. Available: https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware (Accessed: Nov. 15, 2026).

[22] National Audit Office, "Investigation: WannaCry cyber attack and the NHS," Dept. Health, London, U.K., Rep. HC 414, Session 2017–2019, Oct. 27, 2017. [Online]. Available: https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/ (Accessed: Nov. 15, 2026).

[23] W. Smart, "Lessons learned review of the WannaCry ransomware cyber attack," Dept. Health Social Care/NHS England, London, U.K., Feb. 1, 2018. [Online]. Available: https://www.england.nhs.uk/wp-content/uploads/2018/02/lessons-learned-review-wannacry-ransomware-cyber-attack-cio-review.pdf (Accessed: Nov. 15, 2026).

[24] The White House, "Statement from the Press Secretary," Feb. 15, 2018. [Online]. Available: https://trumpwhitehouse.archives.gov/briefings-statements/statement-press-secretary-25/ (Accessed: Nov. 15, 2026).

[25] L. Ablon and A. Bogart, *Zero Days, Thousands of Nights: The Life and Times of Zero-Day Vulnerabilities and Their Exploits*, Rep. RR-1751, RAND Corp., Santa Monica, CA, USA, 2017, doi: 10.7249/RR1751. (⚠ números conferidos só em fonte secundária)

[26] A. Schwartz and R. Knake, "Government's role in vulnerability disclosure: Creating a permanent and accountable vulnerability equities process," Belfer Center for Science and Int. Affairs, Harvard Kennedy School, Cambridge, MA, USA, Discussion Paper 2016-04, Jun. 2016. [Online]. Available: https://www.belfercenter.org/publication/governments-role-vulnerability-disclosure-creating-permanent-and-accountable (Accessed: Nov. 15, 2026).

[27] S. B. Wicker, "The ethics of zero-day exploits," *Commun. ACM*, vol. 64, no. 1, pp. 97–103, Jan. 2021, doi: 10.1145/3393670. (⚠ subtítulo não confirmado)

[28] B. Smith, "The need for urgent collective action to keep people safe online: Lessons from last week's cyberattack," Microsoft On the Issues, May 14, 2017. [Online]. Available: https://blogs.microsoft.com/on-the-issues/2017/05/14/need-urgent-collective-action-keep-people-safe-online-lessons-last-weeks-cyberattack/ (Accessed: Nov. 15, 2026). (⚠ autoria não aparece no texto lido)

[29] Symantec Security Response, "What you need to know about the WannaCry ransomware," Symantec Threat Intelligence Blog. [Online]. Available: https://symantec-enterprise-blogs.security.com/threatintelligence/wannacry-ransomware-attack (Accessed: Nov. 15, 2026). (⚠ data do post: a página mostra 23/10/2017 com atualizações de maio/2017)

[30] A. Chernikova, N. Gozzi, S. Boboila, N. Perra, T. Eliassi-Rad, and A. Oprea, "Modeling self-propagating malware with epidemiological models," 2022, arXiv:2208.03276. [Online]. Available: https://arxiv.org/abs/2208.03276 (Accessed: Nov. 15, 2026). (⚠ preprint)

### Reserva (verificados, menos relevantes ou com ressalva mais séria — usar só se necessário)

[R1] J. Vostoupal, "Stuxnet vs WannaCry and Albania: Cyber-attribution on trial," *Comput. Law Secur. Rev.*, vol. 54, Art. 106008, Sep. 2024, doi: 10.1016/j.clsr.2024.106008. [V-meta]

[R2] C. Adams, "Learning the lessons of WannaCry," *Comput. Fraud Secur.*, vol. 2018, no. 9, pp. 6–9, 2018, doi: 10.1016/S1361-3723(18)30084-8. [V-meta]

[R3] L. J. Trautman and P. Ormerod, "WannaCry, ransomware, and the emerging threat to corporations," SSRN, 2018, doi: 10.2139/ssrn.3238293. [V-meta]

[R4] P.-H. P. Le, L. X. Dang, Q. N. Do, C. N. Hoang, and L. V. Nguyen, "EternalBlue exploit: Definitions and working mechanism," in *Trends in Sustainable Computing and Machine Intelligence* (Algorithms for Intelligent Systems). Singapore: Springer, 2025, pp. 1–13, doi: 10.1007/978-981-96-1452-3_1. [V-meta; resumo não obtido]

[R5] M. Aljaidi *et al.*, "NHS WannaCry ransomware attack: Technical explanation of the vulnerability, exploitation, and countermeasures," in *Proc. 2022 Int. Eng. Conf. Elect., Energy, Artif. Intell. (EICEEAI)*, Nov. 2022, pp. 1–6, doi: 10.1109/EICEEAI56378.2022.10050485. [V-meta; resumo em bases de dados parece trocado]

[R6] A. Novokhrestov, A. Kalyakin, A. Kovalenko, and V. Repkin, "Creating a vulnerable node based on the vulnerability MS17-010," arXiv:2401.14979, Jan. 2024. [Online]. Available: https://arxiv.org/abs/2401.14979 [preprint]

[R7] C. G. Cordero, E. Vasilomanolakis, A. Wainakh, M. Mühlhäuser, and S. Nadjm-Tehrani, "On generating network traffic datasets with synthetic attacks for intrusion detection," arXiv:1905.00304, May 2019. [Online]. Available: https://arxiv.org/abs/1905.00304 [preprint; tangencial]

[R8] US-CERT/CISA, "Microsoft SMBv1 vulnerability," alert, Mar. 16, 2017. [Online]. Available: https://www.cisa.gov/news-events/alerts/2017/03/16/microsoft-smbv1-vulnerability

[R9] boB Rudis, "Wanna Decryptor (WNCRY) ransomware explained," Rapid7 Blog, May 12, 2017. [Online]. Available: https://www.rapid7.com/blog/post/2017/05/12/wanna-decryptor-wncry-ransomware-explained/

[R10] S. Dillon, "Demystifying MS17-010: Reverse engineering the ETERNAL exploits," presented at DEF CON 26, Las Vegas, NV, USA, Aug. 12, 2018. [Online]. Available: https://infocondb.org/con/def-con/def-con-26/demystifying-ms17-010-reverse-engineering-the-eternal-exploits

[R11] L. Ablon and A. Bogart, "Bug collisions meet government vulnerability disclosure (Zero Days, Thousands of Nights)," presented at Black Hat USA, Las Vegas, NV, USA, 2017. [Online]. Available: https://www.blackhat.com/docs/us-17/thursday/us-17-Ablon-Bug-Collisions-Meet-Government-Vulnerability-Disclosure-Zero-Days-Thousands-Of-Nights-RAND.pdf

[R12] A. Greenberg, *Sandworm*. New York, NY, USA: Doubleday, 2019. (⚠ subtítulo e capítulos não confirmados) 

[R13] N. Perlroth, *This Is How They Tell Me the World Ends*. London, U.K.: Bloomsbury, 2021. (⚠ subtítulo e capítulos não confirmados)

[R14] M. Hutchins ("MalwareTech"), "How to accidentally stop a global cyber attacks," May 13, 2017. [Online]. Available: https://malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html (⚠ site retorna 403 para clientes automatizados; conteúdo NÃO lido por mim; abrir manualmente antes de citar)

### Inferences
- Recomendação de núcleo para 4 páginas: [1]–[11], [14], [21]–[26] (cerca de 18 refs) com 2–3 do restante conforme o foco do grupo.
- Fontes web têm "Accessed" a preencher com a data real de acesso do grupo.

### Gaps (resumo de verificação)
- **Verificados [V] com abertura direta**: [1], [3], [4], [14]–[19], [21]–[24], [26], [10] (páginas lidas); DOIs [2], [6]–[9], [11]–[13], [25], [27] conferidos no Crossref/OpenAlex.
- **Ressalvas**: [12] páginas; [13] ano/local; [20] autoria via busca; [25] números só via fontes secundárias; [27] subtítulo; [28] autoria; [29] data do post; [30] preprint.
- **Sites com erro/bloqueio**: malwiki.org (403 + redirecionamento suspeito), malwaretech.com (403), cloudflare.com e cisa.gov direto (403 a bots, mas abrem em navegador), sol.sbc.org.br e doi.org/10.5753 (403 a bots), cert.br/orbilu/malpedia (erro de certificado no meu cliente), RAND e PeerJ (403 ao WebFetch). URLs 404: Europol press release, NCSC statement, Symantec "Lazarus" (URL antiga), Rapid7 URL antiga, Imperva /eternalblue, CrowdStrike cybersecurity-101, Kaspersky encyclopedia.
- Trabalhos recentes (2025–2026) específicos sobre EternalBlue em venues sólidos: apenas Le et al. 2025 (Springer; resumo não obtido) — o campo parece pouco ativo; há registros do NVD atualizados em 08/2026 (CVE-2017-0144), indicando que a falha segue catalogada no KEV.
