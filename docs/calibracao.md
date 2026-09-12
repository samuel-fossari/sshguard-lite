# Calibração — corpus sintético dirigido (Fase 8)

Validação formal da seção 11 da especificação. Não usamos rótulos do AIT-LDS
para força bruta SSH (limitação da seção 6.1). Os cinco arquivos em
`data/samples/calibracao/` foram desenhados com o resultado esperado conhecido.

Limiares atuais (não alterados após a rodada):

| Variável | Valor |
|---|---|
| `BRUTE_FORCE_THRESHOLD` | 5 eventos |
| `BRUTE_FORCE_WINDOW_SECONDS` | 60 |
| `SCANNING_THRESHOLD` | 3 usuários distintos |
| `SCANNING_WINDOW_SECONDS` | 120 |
| `COMPROMISE_WINDOW_SECONDS` | 300 |

## Resultados

| Arquivo | Cenário | Esperado | Obtido |
|---|---|---|---|
| `01_limiar_exato.log` | RD1 com 5 falhas no mesmo IP; RD2 com 3 usuários distintos noutro IP | alerta `forca_bruta` em `203.0.113.10`; alerta `scanning` em `203.0.113.11` | ok |
| `02_abaixo_limiar.log` | 4 falhas (RD1) e 2 usuários distintos (RD2) | nenhum alerta | ok |
| `03_trafego_normal.log` | só logins aceitos/esparsos e ruído (cron, publickey) | nenhum alerta | ok |
| `04_multiplos_ips.log` | dois IPs com 5 falhas cada, intercalados | um `forca_bruta` por IP, 5 tentativas cada, sem misturar | ok |
| `05_rd3_janela.log` | RD1 + aceite 232s depois (`203.0.113.50`); RD1 + aceite 352s depois (`203.0.113.60`) | `comprometimento` só no primeiro IP | ok |

Nenhum cenário de fronteira exigiu mudar limiar ou lógica. Os valores
iniciais da seção 7 permaneceram.
