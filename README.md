# sshguard-lite

Ferramenta de linha de comando (CLI) em Python que analisa arquivos `auth.log` do Linux (formato syslog/`sshd`) e detecta tentativas de força bruta SSH, enumeração de usuários e indício de comprometimento após uma rajada de falhas.

> Repositório público: *a preencher após a publicação no GitHub.*

---

## Descrição do problema

Servidores Linux expostos na Internet acumulam, no `auth.log`, tentativas repetidas de autenticação SSH — senha errada contra um usuário existente (`Failed password`) ou tentativas contra contas que não existem (`Invalid user`). Isoladas, essas linhas são ruído; em sequência, a partir do mesmo endereço IP e em pouco tempo, caracterizam um ataque de **força bruta**. Uma variante relacionada é a **enumeração/scanning de usuários**: o mesmo IP testa muitos nomes distintos. Se, depois de uma rajada de falhas, o `sshd` registrar `Accepted password` daquele IP, há indício de que a força bruta **obteve sucesso**.

O problema prático é transformar um arquivo de log estático, potencialmente grande e cheio de linhas irrelevantes (cron, PAM, `publickey`), numa lista objetiva de IPs, usuários e janelas de tempo — sem depender de um IDS em tempo real nem de serviços externos.

---

## Motivação

- É um problema real e bem documentado de segurança de sistemas.
- O formato de entrada (`auth.log` / syslog do `sshd`) é padronizado e reconhecível em distribuições Linux.
- Existe um dataset acadêmico público com rótulos, o [AIT Log Data Set V2.0](https://zenodo.org/records/5789064), que serviu para validar o **formato** do parser — ainda que, como registrado em [Limitações conhecidas](#limitações-conhecidas), os testbeds verificados **não** contenham força bruta SSH rotulada.
- A ferramenta é reproduzível com Python 3.10+ e biblioteca padrão apenas: `git clone`, ambiente virtual e um único comando de execução.

---

## Objetivo do artefato

Construir um software funcional de Cibersegurança (Tarefa 3 da disciplina do professor Diego Luis Kreutz) que, dado o caminho de um `auth.log` local:

1. extraia os eventos de autenticação SSH reconhecidos;
2. aplique as regras de detecção (força bruta, scanning e comprometimento);
3. emita um relatório em texto ou JSON, listando IPs, usuários e janelas de tempo.

O artefato opera **offline**, sobre arquivos estáticos, e não toma nenhuma ação automática sobre a rede.

---

## Principais funcionalidades

Pipeline: arquivo `.log` → parser → regras → relatório (texto ou JSON).

### Regras de detecção

Os parâmetros abaixo estão nomeados em `sshguard_lite/rules.py` (não são números soltos na lógica).

| ID | Tipo de alerta | Critério atual | Constantes |
|---|---|---|---|
| RD1 | `forca_bruta` | Mesmo IP com **5 ou mais** falhas (`failed_password` ou `invalid_user`) agrupadas por gap ≤ **60 segundos** | `BRUTE_FORCE_THRESHOLD = 5`, `BRUTE_FORCE_WINDOW_SECONDS = 60` |
| RD2 | `scanning` | Mesmo IP com **3 ou mais usuários distintos** nas falhas, gap ≤ **120 segundos** | `SCANNING_THRESHOLD = 3`, `SCANNING_WINDOW_SECONDS = 120` |
| RD3 | `comprometimento` | Após um alerta de RD1, um `accepted_password` do mesmo IP **depois** do fim da rajada e em até **300 segundos** | `COMPROMISE_WINDOW_SECONDS = 300` |

- Falhas que contam para RD1 e RD2: `Failed password for …`, `Failed password for invalid user …` e `Invalid user …`. `Accepted password` **não** entra no limiar dessas duas regras.
- RD1 e RD2 são passagens independentes: o mesmo IP pode gerar os dois alertas ao mesmo tempo (volume ≠ diversidade de usuários).
- RD3 depende dos alertas da RD1 (não é uma passagem solta sobre o log). No máximo um alerta de comprometimento por rajada de força bruta; `usuarios_envolvidos` fica só com a conta que logou.

### Formatos de saída

- **Texto** (padrão): cabeçalho com linhas processadas, período e quantidade de alertas; lista ordenada por número de tentativas (desempate: IP, depois tipo `forca_bruta` → `scanning` → `comprometimento`).
- **JSON** (`--json`): mesmos dados, schema com `linhas_processadas`, `eventos_extraidos`, `periodo_inicio`, `periodo_fim`, `alertas_encontrados` e `alertas`. Timestamps em ISO 8601; período `null` se não houver eventos; `alertas` é lista vazia (nunca `null`) se não houver alerta.

Não há `--threshold`, `--window`, modo ao vivo, geolocalização nem bloqueio de IP.

---

## Dependências

Nenhuma dependência externa. O projeto usa só a biblioteca padrão do Python: `re`, `datetime`, `argparse`, `collections`, `json`, `pathlib`, `unittest` (testes).

O `requirements.txt` da raiz existe para deixar isso explícito: `pip install -r requirements.txt` é um no-op seguro.

---

## Requisitos de execução

- Python **3.10 ou superior** (desenvolvimento e suíte atuais rodaram em Python 3.12.3).
- Sistema operacional qualquer com esse interpretador (Linux, macOS ou Windows); não há caminhos fixos de SO no código.
- Um arquivo `auth.log` local para analisar. A ferramenta **não** acessa a rede em tempo de execução.

Em várias distros Linux modernas o comando `python` **não existe** (só `python3`), a menos que o pacote de compatibilidade esteja instalado. Os blocos abaixo mostram as duas formas, no mesmo estilo da ativação do venv.

---

## Instruções de instalação

```bash
git clone <URL-DO-REPOSITORIO>
cd sshguard-lite
python3 -m venv .venv              # Linux/macOS
python -m venv .venv               # Windows
source .venv/bin/activate          # Linux/macOS
.venv\Scripts\activate             # Windows
pip install -r requirements.txt    # nenhum pacote a instalar
```

---

## Instruções de execução

Da raiz do repositório, com o ambiente virtual ativo:

```bash
python3 -m sshguard_lite CAMINHO/PARA/auth.log                 # Linux/macOS
python -m sshguard_lite CAMINHO/PARA/auth.log                  # Windows

python3 -m sshguard_lite CAMINHO/PARA/auth.log --year 2022     # Linux/macOS
python -m sshguard_lite CAMINHO/PARA/auth.log --year 2022      # Windows

python3 -m sshguard_lite CAMINHO/PARA/auth.log --json          # Linux/macOS
python -m sshguard_lite CAMINHO/PARA/auth.log --json           # Windows

python3 -m sshguard_lite CAMINHO/PARA/auth.log --year 2022 --json   # Linux/macOS
python -m sshguard_lite CAMINHO/PARA/auth.log --year 2022 --json    # Windows
```

- Argumento posicional obrigatório: caminho do `auth.log`.
- `--year` (opcional): ano usado nos timestamps syslog (que não trazem ano). Sem a flag, o parser usa o ano corrente do sistema. O recorte `data/samples/auth.log` precisa de `--year 2022`.
- `--json` (opcional): troca o texto por JSON; os dois formatos não saem juntos.

Códigos de saída do processo:

| Código | Significado |
|---|---|
| `0` | execução concluída (com ou sem alertas) |
| `1` | erro de uso (argumento inválido ou arquivo ausente/vazio) |
| `2` | falha inesperada |

Arquivo inexistente escreve em *stderr* (sem traceback) e termina com código **1**. Exemplo verificado:

```bash
python3 -m sshguard_lite nao_existe.log    # Linux/macOS
python -m sshguard_lite nao_existe.log     # Windows
echo $?                                    # Linux/macOS: imprime 1
echo %ERRORLEVEL%                          # Windows: imprime 1
```

```
erro: Arquivo não encontrado: nao_existe.log
```

---

## Exemplos de uso

Comandos e saídas abaixo foram gerados de fato contra `data/samples/auth.log` (296 linhas; 24 eventos extraídos).

### Texto

```bash
python3 -m sshguard_lite data/samples/auth.log --year 2022    # Linux/macOS
python -m sshguard_lite data/samples/auth.log --year 2022     # Windows
```

```
Análise de auth.log concluída
Linhas processadas: 296
Período: 2022-01-24 03:10:01 a 2022-01-24 03:10:37
Alertas encontrados: 3

[FORÇA BRUTA] IP 203.0.113.88 — 22 tentativas — usuários: admin, ubuntu, test, oracle, guest, root — 03:10:01 a 03:10:33
[SCANNING] IP 203.0.113.88 — 22 tentativas — usuários: admin, ubuntu, test, oracle, guest, root — 03:10:01 a 03:10:33
[COMPROMETIMENTO] IP 203.0.113.88 — 22 tentativas — usuários: root — 03:10:01 a 03:10:37
```

### JSON

```bash
python3 -m sshguard_lite data/samples/auth.log --year 2022 --json    # Linux/macOS
python -m sshguard_lite data/samples/auth.log --year 2022 --json     # Windows
```

```json
{
  "linhas_processadas": 296,
  "eventos_extraidos": 24,
  "periodo_inicio": "2022-01-24T03:10:01",
  "periodo_fim": "2022-01-24T03:10:37",
  "alertas_encontrados": 3,
  "alertas": [
    {
      "tipo_alerta": "forca_bruta",
      "ip_origem": "203.0.113.88",
      "usuarios_envolvidos": [
        "admin",
        "ubuntu",
        "test",
        "oracle",
        "guest",
        "root"
      ],
      "numero_tentativas": 22,
      "janela_inicio": "2022-01-24T03:10:01",
      "janela_fim": "2022-01-24T03:10:33"
    },
    {
      "tipo_alerta": "scanning",
      "ip_origem": "203.0.113.88",
      "usuarios_envolvidos": [
        "admin",
        "ubuntu",
        "test",
        "oracle",
        "guest",
        "root"
      ],
      "numero_tentativas": 22,
      "janela_inicio": "2022-01-24T03:10:01",
      "janela_fim": "2022-01-24T03:10:33"
    },
    {
      "tipo_alerta": "comprometimento",
      "ip_origem": "203.0.113.88",
      "usuarios_envolvidos": [
        "root"
      ],
      "numero_tentativas": 22,
      "janela_inicio": "2022-01-24T03:10:01",
      "janela_fim": "2022-01-24T03:10:37"
    }
  ]
}
```

---

## Estrutura do repositório

```text
sshguard-lite/
├── README.md
├── requirements.txt
├── .gitignore
├── sshguard_lite/
│   ├── __init__.py
│   ├── __main__.py          # python3 -m sshguard_lite (Linux/macOS) / python -m sshguard_lite (Windows)
│   ├── cli.py               # argumentos, metadados, códigos de saída
│   ├── parser.py            # extração de eventos do auth.log
│   ├── rules.py             # RD1, RD2, RD3
│   └── report.py            # texto e JSON
├── data/
│   ├── README.md
│   └── samples/
│       ├── auth.log         # recorte híbrido (AIT-LDS + sintético)
│       ├── SOURCE.txt       # proveniência do recorte
│       └── calibracao/
│           ├── 01_limiar_exato.log
│           ├── 02_abaixo_limiar.log
│           ├── 03_trafego_normal.log
│           ├── 04_multiplos_ips.log
│           └── 05_rd3_janela.log
├── docs/
│   └── calibracao.md        # registro da Fase 8
└── tests/
    ├── test_smoke.py
    ├── test_parser.py
    ├── test_rules.py
    ├── test_report.py
    ├── test_cli.py
    └── test_calibracao.py
```

O dataset AIT-LDS completo **não** entra no Git (é pesado). Instruções de onde baixá-lo estão em `data/README.md`.

---

## Testes

A suíte usa `unittest` da biblioteca padrão (**47 testes** no estado atual: parser, regras, relatório, CLI, smoke e calibração).

```bash
python3 -m unittest discover -s tests -v    # Linux/macOS
python -m unittest discover -s tests -v     # Windows
```

Os cinco cenários de fronteira (limiar exato, abaixo do limiar, tráfego normal, múltiplos IPs, RD3 dentro/fora de 300 s) estão em `data/samples/calibracao/` e são exercitados por `tests/test_calibracao.py`. O registro do que cada cenário deveria (e de fato) produzir está em `docs/calibracao.md`. Nessa rodada os limiares 5/60 s, 3/120 s e 300 s se comportaram como especificado; nenhum valor foi recalibrado.

---

## Limitações conhecidas

- **Recorte de exemplo híbrido.** `data/samples/auth.log` junta 272 linhas reais do host `intranet_server` do testbed `russellmitchell` (AIT-LDS) com 24 linhas sintéticas de `sshd` (`Failed password` / `Invalid user` / um `Accepted password`) no IP de documentação `203.0.113.88`. O trecho sintético **não** faz parte do *ground truth* do dataset. Motivo: nos três testbeds inspecionados (`russellmitchell`, `harrison`, `wheeler`) **não há** força bruta SSH rotulada no `auth.log` — os logins SSH são por chave pública; o ataque rotulado no recorte real de `russellmitchell` é escalação `su`/`sudo` após webshell, com quebra de senha **offline** (John the Ripper), não tentativas de rede contra o `sshd`. Detalhes em `data/samples/SOURCE.txt`.
- **Validação formal sintético-dirigida.** A Fase 8 não compara alertas com rótulos de um ataque SSH real. Usa o corpus de cinco arquivos em `data/samples/calibracao/`, cada um com resultado esperado definido de antemão. Isso é limitação conhecida e justificada pela seção 6.1 da especificação, não uma omissão.
- **Timestamps sem fuso horário.** O syslog tradicional não traz ano nem timezone. O parser preenche o ano com `--year` ou com o ano corrente do sistema; não interpreta fuso. Os horários do relatório (texto e JSON) são *naive*.
- **Não é um IDS em tempo real.** Só lê arquivos estáticos; não acompanha *stream* ao vivo.
- **Não bloqueia IPs.** Não há integração com firewall, `fail2ban` nem ação automática.
- **Só SSH no `auth.log`.** Não analisa HTTP, FTP nem outros protocolos. Linhas que não batem com os padrões `sshd` da especificação são ignoradas.
- **Limiares não são configuráveis pela CLI.** Não existe `--threshold` nem `--window`; mudar valores exige editar as constantes em `sshguard_lite/rules.py`.
- **Sem interface gráfica, geolocalização ou consultas externas.** A ferramenta funciona offline.

---

## Referências

- Landauer, M. *et al.* **AIT Log Data Set V2.0** (AIT-LDS). Zenodo, 2022. DOI: [10.5281/zenodo.5789064](https://doi.org/10.5281/zenodo.5789064). Disponível em: <https://zenodo.org/records/5789064>.
- Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M. e Rauber, A. Maintainable Log Datasets for Evaluation of Intrusion Detection Systems. *IEEE Transactions on Dependable and Secure Computing*, 2023. DOI: [10.1109/TDSC.2022.3201582](https://doi.org/10.1109/TDSC.2022.3201582).
- Empacotamento V2.1 do mesmo conteúdo de logs, com arquivos `*_no-pcaps.zip` menores (usado na extração do recorte): <https://zenodo.org/records/19483937>.
- Proveniência do recorte de desenvolvimento: `data/samples/SOURCE.txt`.
- Calibração dos limiares no corpus sintético: `docs/calibracao.md`.
