# Quebra de senha de ZIP via Wordlist (terminal)

Atividade individual de Segurança da Informação. O script `crack_zip.py`
recebe um arquivo `.zip` protegido por senha e uma wordlist, e tenta cada
senha da lista até encontrar a correta (ataque de dicionário).

Inspirado nos conceitos do projeto [DeschaveZIP](https://github.com/lkaranl/DeschaveZIP),
mas reimplementado do zero, em terminal, sem GTK, já que a atividade é individual.

## Como funciona

1. **Detecção do tipo de criptografia**: o script lê os cabeçalhos do ZIP
   (`flag_bits` e `compress_type` de cada entrada) para identificar se a
   proteção é `ZipCrypto` (o método tradicional, suportado nativamente pelo
   Python) ou `AES` (mais moderno, que o módulo `zipfile` do Python **não**
   sabe descriptografar — nesse caso o script avisa e sugere usar o 7-Zip).
2. **Ataque de dicionário**: para cada senha da wordlist, tenta abrir/ler um
   arquivo dentro do ZIP com `zipfile.ZipFile.read(nome, pwd=senha)`. Se a
   senha estiver errada, o Python levanta `RuntimeError` (senha inválida)
   ou `zipfile.BadZipFile` (CRC não confere) — o script captura esses erros
   e passa para a próxima senha.
3. **Paralelismo**: usa `ThreadPoolExecutor` para testar várias senhas ao
   mesmo tempo (padrão: 8 threads), com um `threading.Event` para parar
   assim que a senha correta é encontrada.
4. **Extração opcional**: com `--extract`, se a senha for encontrada, o
   conteúdo do ZIP já é extraído automaticamente para a pasta indicada.

## Requisitos

- Python 3.6+ (usa apenas biblioteca padrão: `zipfile`, `argparse`,
  `concurrent.futures`, `threading`, `pathlib` — nada para instalar)

## Uso

```bash
python3 crack_zip.py -z arquivo.zip -w wordlist.txt
```

Opções:

| Flag         | Descrição                                              | Padrão |
|--------------|----------------------------------------------------------|--------|
| `-z / --zip`       | Caminho do arquivo ZIP protegido                    | obrigatório |
| `-w / --wordlist`  | Caminho da wordlist (uma senha por linha)           | obrigatório |
| `-t / --threads`   | Número de threads paralelas                         | 8 |
| `--extract`        | Pasta onde extrair o conteúdo se a senha for achada | (não extrai) |

## Demonstração rápida (incluída neste pacote)

Este pacote já vem com um ZIP de teste (`teste_matrix.zip`, protegido com a
senha `matrix`) e uma wordlist de exemplo (`wordlist_exemplo.txt`) que
contém a palavra `matrix` entre outras senhas comuns — prontos para testar:

```bash
python3 crack_zip.py -z teste_matrix.zip -w wordlist_exemplo.txt
```

Saída esperada:

```
[*] Tipo de criptografia detectado:  ZipCrypto
[*] Wordlist carregada:              30 senhas (wordlist_exemplo.txt)
[+] SENHA ENCONTRADA: 'matrix'
```

## Para usar com o arquivo do professor

Quando você tiver o arquivo ZIP real da atividade (o "arquivo em anexo"
mencionado no enunciado, cuja senha é `matrix`), basta apontar o script
para ele:

```bash
python3 crack_zip.py -z /caminho/para/arquivo_da_atividade.zip -w wordlist_exemplo.txt
```

Como a senha `matrix` já está na wordlist de exemplo, o script deve
encontrá-la rapidamente — ótimo para a demonstração ao vivo em aula.

## Roteiro sugerido para a demonstração em aula

1. Mostrar o ZIP protegido tentando abrir sem senha (mostra que pede senha).
2. Rodar `python3 crack_zip.py -z arquivo.zip -w wordlist_exemplo.txt` e
   explicar em voz alta o que está acontecendo: detecção do tipo de
   criptografia → tentativa senha a senha → parada ao encontrar.
3. Rodar de novo com `--extract ./saida` para mostrar a extração automática
   do conteúdo assim que a senha é confirmada.
4. (Opcional) Trocar a wordlist por uma sem a senha `matrix` para mostrar o
   caso de falha, e depois por uma wordlist maior (ex.: `rockyou.txt`) para
   falar sobre tempo de execução e efetividade de wordlists reais.

## Limitações (bom mencionar na apresentação)

- Só quebra **ZipCrypto** nativamente. ZIPs com criptografia **AES**
  (comuns em arquivos gerados pelo WinZip/7-Zip modernos) exigiriam uma
  ferramenta externa como o 7-Zip, assim como o próprio DeschaveZIP faz.
- É um ataque de **dicionário**: só encontra a senha se ela estiver na
  wordlist usada. Não é força bruta exaustiva.

## Aviso

Use apenas em arquivos que você tem autorização para testar (seus
próprios arquivos ou material fornecido pela disciplina).
