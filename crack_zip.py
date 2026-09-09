#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
crack_zip.py
Ataque de dicionário contra arquivos ZIP para atividade de Segurança da Informação.

Uso:
    python3 crack_zip.py -z teste_matrix.zip -w wordlist_exemplo.txt

Exemplo:
    Se a senha do ZIP estiver na wordlist como "matrix", o programa deverá
    informar:

        [+] SENHA ENCONTRADA: 'matrix'

Use somente em arquivos para os quais você possui autorização.
"""

import argparse
import concurrent.futures
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path


class ZipCracker:
    def __init__(self, zip_path, wordlist_path):
        self.zip_path = Path(zip_path)
        self.wordlist_path = Path(wordlist_path)

        self.is_running = False
        self.current_password = 0
        self.total_passwords = 0
        self.found_password = None
        self.encryption_type = None

        # Mantém a ideia do código original: no máximo 8 workers.
        self.max_workers = min(8, os.cpu_count() or 4)

        self._found_password_lock = threading.Lock()
        self._progress_queue = queue.Queue()

        self._7z_binary = self._find_7z_binary()

    def _find_7z_binary(self):
        """Procura o executável do 7-Zip no sistema."""
        possible_paths = [
            "/usr/bin/7z",
            "/usr/local/bin/7z",
            "/usr/bin/7za",
            "/usr/local/bin/7za",
            "/opt/homebrew/bin/7z",
            "/opt/local/bin/7z",
        ]

        if sys.platform.startswith("win"):
            possible_paths.extend([
                r"C:\Program Files\7-Zip\7z.exe",
                r"C:\Program Files (x86)\7-Zip\7z.exe",
                os.path.join(
                    os.environ.get("ProgramFiles", r"C:\Program Files"),
                    "7-Zip",
                    "7z.exe",
                ),
                os.path.join(
                    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                    "7-Zip",
                    "7z.exe",
                ),
            ])

        for path in possible_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        try:
            command = "where" if sys.platform.startswith("win") else "which"
            names = ["7z.exe", "7za.exe"] if sys.platform.startswith("win") else ["7z", "7za"]

            for name in names:
                result = subprocess.run(
                    [command, name],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError):
            pass

        return None

    def _get_compression_name(self, compress_type):
        compression_types = {
            zipfile.ZIP_STORED: "Store (Sem compressão)",
            zipfile.ZIP_DEFLATED: "Deflate",
            zipfile.ZIP_BZIP2: "BZip2",
            zipfile.ZIP_LZMA: "LZMA",
        }
        return compression_types.get(compress_type, "Desconhecido")

    def _check_aes_encryption(self, info):
        """
        Detecta AES pela convenção do ZIP.

        O método mais confiável disponível no zipfile para identificar
        WinZip AES é compress_type == 99 (método AES registrado no ZIP).
        """
        return info.compress_type == 99

    def detect_encryption_type(self):
        """
        Retorna informações sobre a proteção do ZIP.

        AES não é tratado pelo zipfile nativo; quando disponível,
        o 7-Zip é usado para testar a senha.
        """
        result = {
            "is_encrypted": False,
            "encryption_type": "Nenhuma",
            "supported": True,
            "encrypted_files": 0,
            "total_files": 0,
            "files_info": [],
            "has_external_support": bool(self._7z_binary),
        }

        try:
            with zipfile.ZipFile(self.zip_path) as zip_file:
                infos = zip_file.infolist()
                result["total_files"] = len(infos)

                has_aes = False

                for info in infos:
                    encrypted = bool(info.flag_bits & 0x1)
                    is_aes = encrypted and self._check_aes_encryption(info)

                    if encrypted:
                        result["is_encrypted"] = True
                        result["encrypted_files"] += 1

                    if is_aes:
                        has_aes = True

                    result["files_info"].append({
                        "name": info.filename,
                        "size": info.file_size,
                        "encrypted": encrypted,
                        "encryption_type": "AES" if is_aes else (
                            "ZipCrypto" if encrypted else "Nenhuma"
                        ),
                        "compression": self._get_compression_name(info.compress_type),
                    })

                if has_aes:
                    result["encryption_type"] = "AES (Avançada)"
                    result["supported"] = bool(self._7z_binary)
                elif result["is_encrypted"]:
                    result["encryption_type"] = "ZipCrypto (Padrão)"

            return result

        except Exception as e:
            result["error"] = str(e)
            return result

    def _get_test_files(self):
        """Obtém somente arquivos reais e não vazios para validar a senha."""
        with zipfile.ZipFile(self.zip_path) as zip_file:
            files = [
                info for info in zip_file.infolist()
                if not info.is_dir() and info.file_size > 0
            ]

        return files

    def crack_password_with_7z_detailed(self, password, zip_path=None):
        """Testa uma senha usando o 7-Zip."""
        if self._7z_binary is None:
            return False, "7-Zip não encontrado no sistema"

        if zip_path is None:
            zip_path = str(self.zip_path)

        try:
            # O comando "t" testa a integridade sem precisar manter
            # os arquivos extraídos.
            command = [
                self._7z_binary,
                "t",
                "-y",
                "-p" + password,
                zip_path,
            ]

            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )

            output = (process.stdout + "\n" + process.stderr).lower()

            if process.returncode == 0 and "everything is ok" in output:
                return True, None

            return False, "Senha incorreta"

        except subprocess.TimeoutExpired:
            return False, "Timeout ao verificar senha"
        except Exception as e:
            return False, f"Erro ao verificar senha: {e}"

    def crack_password_with_7z(self, password):
        success, _ = self.crack_password_with_7z_detailed(password)
        return success

    def _test_zipcrypto_password(self, password, files_to_check):
        """
        Testa uma senha ZipCrypto diretamente com o zipfile.

        A senha é testada exatamente como aparece na wordlist.
        Para o ZIP da atividade, o arquivo conteudo.txt é suficiente
        para validar a senha através do CRC.
        """
        try:
            password_bytes = password.encode("utf-8")

            with zipfile.ZipFile(self.zip_path, "r") as zip_file:
                for info in files_to_check:
                    try:
                        # read() força a descriptografia e a verificação
                        # de integridade do conteúdo.
                        zip_file.read(info, pwd=password_bytes)
                        return True
                    except (RuntimeError, zipfile.BadZipFile, zipfile.error):
                        continue

            return False

        except (OSError, zipfile.BadZipFile, zipfile.error):
            return False

    def crack_password(self, pause_check=None, cancel_check=None):
        """
        Executa o ataque de dicionário.

        Para ZipCrypto, as senhas da wordlist são testadas em ordem.
        O processamento paralelo continua disponível, mas a fila é
        controlada para que nenhuma senha seja perdida.
        """
        self.current_password = 0
        self.found_password = None
        self.is_running = True

        try:
            if not self.zip_path.exists():
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": f"Arquivo ZIP não encontrado: {self.zip_path}",
                }
                return

            if not self.wordlist_path.exists():
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": f"Wordlist não encontrada: {self.wordlist_path}",
                }
                return

            encryption_info = self.detect_encryption_type()

            if "error" in encryption_info:
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": f"Erro ao analisar o ZIP: {encryption_info['error']}",
                }
                return

            if not encryption_info["is_encrypted"]:
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": "O arquivo ZIP não está protegido por senha.",
                }
                return

            self.encryption_type = encryption_info["encryption_type"]

            try:
                files_to_check = self._get_test_files()
            except Exception as e:
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": f"Erro ao obter arquivos do ZIP: {e}",
                }
                return

            if not files_to_check:
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": "O ZIP não contém arquivos não vazios para testar.",
                }
                return

            # utf-8-sig remove automaticamente BOM, quando existir.
            try:
                with open(
                    self.wordlist_path,
                    "r",
                    encoding="utf-8-sig",
                    errors="replace",
                ) as wordlist:
                    # Remove espaços/tabs no início ou fim da linha.
                    # Isso é importante porque a sua wordlist contém tabs
                    # depois de várias senhas, inclusive "matrix".
                    passwords = [
                        line.strip()
                        for line in wordlist
                        if line.strip()
                    ]
            except OSError as e:
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": f"Erro ao abrir a wordlist: {e}",
                }
                return

            if not passwords:
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": "A wordlist está vazia.",
                }
                return

            self.total_passwords = len(passwords)

            yield {
                "current_password": 0,
                "current_text": "",
                "info": (
                    f"Arquivo protegido: {encryption_info['encryption_type']} | "
                    f"{self.total_passwords} senhas | "
                    f"{self.max_workers} threads"
                ),
                "encryption_info": encryption_info,
            }

            is_aes = encryption_info["encryption_type"].startswith("AES")

            if is_aes and not self._7z_binary:
                yield {
                    "current_password": 0,
                    "current_text": "",
                    "error": (
                        "AES detectado, mas o 7-Zip não foi encontrado."
                    ),
                }
                return

            start_time = time.time()

            # Para ZipCrypto, usamos execução sequencial. Isso evita que
            # a concorrência esconda a posição exata da senha e torna o
            # resultado determinístico para a atividade.
            #
            # AES continua usando 7-Zip, também de forma controlada.
            for index, password in enumerate(passwords, start=1):
                if cancel_check and cancel_check():
                    yield {
                        "current_password": index - 1,
                        "current_text": "",
                        "cancelled": True,
                        "info": "Operação cancelada.",
                    }
                    return

                if pause_check:
                    while pause_check():
                        if cancel_check and cancel_check():
                            yield {
                                "current_password": index - 1,
                                "current_text": "",
                                "cancelled": True,
                                "info": "Operação cancelada.",
                            }
                            return
                        time.sleep(0.1)

                self.current_password = index

                if is_aes:
                    success, _ = self.crack_password_with_7z_detailed(password)
                else:
                    success = self._test_zipcrypto_password(
                        password,
                        files_to_check,
                    )

                yield {
                    "current_password": index,
                    "current_text": password,
                }

                if success:
                    self.found_password = password
                    elapsed = time.time() - start_time

                    yield {
                        "current_password": index,
                        "current_text": password,
                        "password": password,
                        "method": "7z" if is_aes else "zipfile",
                        "elapsed": elapsed,
                        "attempts": index,
                    }
                    return

            elapsed = time.time() - start_time

            yield {
                "current_password": self.total_passwords,
                "current_text": "",
                "error": (
                    f"Nenhuma senha encontrada na wordlist. "
                    f"{self.total_passwords} tentativas em {elapsed:.2f}s."
                ),
            }

        except Exception as e:
            yield {
                "current_password": self.current_password,
                "current_text": "",
                "error": f"Erro ao processar arquivo: {e}",
            }
        finally:
            self.is_running = False


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Quebra de senha de arquivos ZIP por ataque de dicionário "
            "(somente para arquivos autorizados)."
        )
    )

    parser.add_argument(
        "-z",
        "--zip",
        required=True,
        type=Path,
        help="Caminho do arquivo ZIP protegido.",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        type=Path,
        help="Caminho da wordlist, uma senha por linha.",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=None,
        help="Número de threads. Padrão: até 8, conforme CPU.",
    )

    parser.add_argument(
        "--extract",
        type=Path,
        default=None,
        help="Pasta para extrair o ZIP após encontrar a senha.",
    )

    args = parser.parse_args()

    if not args.zip.is_file():
        sys.exit(f"[!] Arquivo ZIP não encontrado: {args.zip}")

    if not args.wordlist.is_file():
        sys.exit(f"[!] Wordlist não encontrada: {args.wordlist}")

    if args.threads is not None and args.threads < 1:
        sys.exit("[!] O número de threads deve ser maior que zero.")

    cracker = ZipCracker(args.zip, args.wordlist)

    if args.threads is not None:
        cracker.max_workers = min(args.threads, 32)

    print("=" * 65)
    print("             ZIP DICTIONARY CRACKER")
    print("=" * 65)
    print(f"[*] ZIP:       {args.zip}")
    print(f"[*] Wordlist:  {args.wordlist}")
    print(f"[*] Threads:   {cracker.max_workers}")
    print()

    start = time.time()
    senha_encontrada = None

    for result in cracker.crack_password():
        if "info" in result:
            print(f"[*] {result['info']}")

        if "current_password" in result and result.get("current_text"):
            current = result["current_password"]
            total = cracker.total_passwords

            if current % 25 == 0 or current == total:
                elapsed = time.time() - start
                rate = current / elapsed if elapsed > 0 else 0

                print(
                    f"\r[*] Testadas: {current}/{total} "
                    f"| Velocidade: {rate:.0f} senhas/s",
                    end="",
                    flush=True,
                )

        if "password" in result:
            senha_encontrada = result["password"]

            print()
            print()
            print("=" * 65)
            print(f"[+] SENHA ENCONTRADA: '{senha_encontrada}'")
            print(f"[+] Método: {result.get('method', 'desconhecido')}")
            print(f"[+] Tentativas: {result.get('attempts', '?')}")
            print(f"[+] Tempo: {result.get('elapsed', 0):.2f}s")
            print("=" * 65)

            if args.extract:
                try:
                    args.extract.mkdir(parents=True, exist_ok=True)

                    with zipfile.ZipFile(args.zip) as zip_file:
                        zip_file.extractall(
                            path=args.extract,
                            pwd=senha_encontrada.encode("utf-8"),
                        )

                    print(f"[+] Conteúdo extraído em: {args.extract}")

                except Exception as e:
                    print(f"[!] Senha encontrada, mas não foi possível extrair: {e}")

            break

        if "error" in result:
            print()
            print(f"[-] {result['error']}")

    if senha_encontrada is None:
        print()


if __name__ == "__main__":
    main()
