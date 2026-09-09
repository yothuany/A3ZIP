# Quebra de senha de ZIP via Wordlist (Terminal)


O script `crack_zip.py` recebe um arquivo `.zip` protegido por senha e uma wordlist e tenta cada senha da lista até encontrar a correta, utilizando um **ataque de dicionário**.

O projeto foi inspirado nos conceitos do [DeschaveZIP](https://github.com/lkaranl/DeschaveZIP), porém foi **reimplementado do zero**, em terminal e sem GTK, conforme a proposta da atividade individual.

---

## Estrutura do projeto

```text
A4ZIP/
│
├── crack_zip.py
├── teste_matrix.zip
├── wordlist_exemplo.txt
└── README.md
```


## Como funciona

### 1. Detecção do tipo de criptografia

O script analisa as entradas do arquivo ZIP utilizando informações como `flag_bits` e `compress_type` para identificar se o arquivo utiliza:

* **ZipCrypto** — método tradicional, suportado pelo módulo `zipfile` do Python.
* **AES** — método mais moderno, que não é descriptografado nativamente pelo módulo `zipfile`.

Quando um ZIP utiliza AES, o script pode utilizar o **7-Zip**, caso esteja instalado no sistema.

### 2. 

Para cada senha presente na wordlist, o programa tenta acessar um arquivo dentro do ZIP utilizando:

```python
zipfile.ZipFile.read(nome, pwd=senha)
```

Quando a senha está incorreta, o Python pode gerar erros como `RuntimeError` ou `BadZipFile`. Esses erros são tratados pelo programa e a execução continua com a próxima senha.

A busca termina quando a senha correta é encontrada.

### 3. 

O projeto possui suporte a múltiplas threads utilizando:

```python
ThreadPoolExecutor
```

O número de threads pode ser definido através da opção `-t`.

Por padrão, o programa utiliza até **8 threads**.

### 4. 

Quando a senha é encontrada, é possível extrair automaticamente o conteúdo do ZIP utilizando:

```bash
--extract ./saida
```

---

## Requisitos

* Python **3.6 ou superior**
* Bibliotecas utilizadas da biblioteca padrão do Python:

  * `zipfile`
  * `argparse`
  * `concurrent.futures`
  * `threading`
  * `pathlib`
  * `subprocess`
  * `tempfile`
  * `queue`

Para arquivos **ZipCrypto**, não é necessário instalar bibliotecas Python externas.

Para trabalhar com arquivos **AES**, pode ser necessário ter o **7-Zip** instalado.

---

## Uso

A estrutura básica do comando é:

```bash
python3 crack_zip.py -z arquivo.zip -w wordlist.txt
```

### Opções

| Flag               | Descrição                                                  | Padrão      |
| ------------------ | ---------------------------------------------------------- | ----------- |
| `-z`, `--zip`      | Caminho do arquivo ZIP protegido                           | Obrigatório |
| `-w`, `--wordlist` | Caminho da wordlist, uma senha por linha                   | Obrigatório |
| `-t`, `--threads`  | Número de threads paralelas                                | Até 8       |
| `--extract`        | Pasta onde o conteúdo será extraído após encontrar a senha | Não extrai  |

### Exemplo

Encontrar a senha e extrair o conteúdo:

```bash
python3 crack_zip.py -z arquivo.zip -w wordlist.txt --extract ./saida
```

---

## Demonstração rápida

O projeto possui um ZIP de teste chamado:

```text
teste_matrix.zip
```

Ele é protegido pela senha:

```text
matrix
```

A wordlist:

```text
wordlist_exemplo.txt
```

contém a senha `matrix` entre outras senhas comuns.

Para executar:

```bash
python3 crack_zip.py -z teste_matrix.zip -w wordlist_exemplo.txt
```

### Saída esperada

```text
=================================================================
             ZIP DICTIONARY CRACKER
=================================================================
[*] ZIP:       teste_matrix.zip
[*] Wordlist:  wordlist_exemplo.txt
[*] Threads:   8

[*] Arquivo protegido: ZipCrypto (Padrão) | 602 senhas | 8 threads

[+] SENHA ENCONTRADA: 'matrix'
[+] Método: zipfile
```

---

## Utilização com o arquivo da atividade

Quando estiver disponível o arquivo ZIP fornecido pelo professor, basta informar o caminho do arquivo e da wordlist:

```bash
python3 crack_zip.py -z arquivo_da_atividade.zip -w wordlist_exemplo.txt
```

Como a senha `matrix` está presente na wordlist de exemplo, o programa deverá encontrá-la caso o arquivo utilize a senha indicada no enunciado.

---
