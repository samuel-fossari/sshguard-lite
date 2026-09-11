# Dados de teste

O recorte em `samples/auth.log` é um trecho pequeno de um `auth.log` do
[AIT Log Data Set](https://zenodo.org/records/5789064) (AIT-LDS), usado só
para desenvolvimento rápido. O dataset completo **não entra no Git**.

## Onde baixar o dataset completo

- **AIT Log Data Set V2.0** (registro original): <https://zenodo.org/records/5789064>
- **AIT Log Data Set V2.1** (mesmo conteúdo, com zips `*_no-pcaps` menores): <https://zenodo.org/records/19483937>

O link `https://zenodo.org/records/13168643` apontado em rascunhos da
especificação é o **AIT Netflow Data Set**, não os `auth.log`. Para esta
ferramenta use o AIT-LDS.

Sugestão de armazenamento local (fora do repositório):

```text
~/Documentos/Datasets/AIT-LDS/
```

Para reproduzir o recorte usado neste projeto, baixe
`russellmitchell_no-pcaps.zip` (testbed russellmitchell, sem pcaps) e extraia
o `auth.log` do host alvo documentado em `samples/SOURCE.txt`.

Nota da Fase 0: o AIT-LDS v2.0 não registra força bruta SSH no `auth.log`
(logins por chave; cracking offline com John the Ripper). O recorte em
`samples/auth.log` combina o arquivo real do host `intranet_server` com um
trecho sintético no formato `sshd` da especificação — detalhes em
`samples/SOURCE.txt`.
