"""
Envia arquivos PHP vulneraveis para modelos do Amazon Bedrock pedindo a
correcao das vulnerabilidades. Salva cada resposta em resultados/ e registra
as metricas da chamada em resultados/execucoes.csv.

Uso:
    python3 refatorar_bedrock.py amostras/search.php
    python3 refatorar_bedrock.py amostras/*.php --modelo us.amazon.nova-pro-v1:0
"""

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGIAO_PADRAO = "us-east-2"
MODELO_PADRAO = "amazon.nova-lite-v1:0"
MAX_TOKENS = 4096
PASTA_RESULTADOS = Path("resultados")
CSV_EXECUCOES = PASTA_RESULTADOS / "execucoes.csv"
COLUNAS = ["data_utc", "arquivo", "modelo", "regiao", "tokens_entrada",
           "tokens_saida", "parada", "arquivo_resposta"]

PROMPT = (
    "Voce e um especialista em seguranca de aplicacoes PHP.\n"
    "Corrija as vulnerabilidades de seguranca do codigo abaixo.\n"
    "Regras:\n"
    "1. Devolva o arquivo COMPLETO corrigido, nao apenas trechos.\n"
    "2. Preserve o comportamento funcional original.\n"
    "3. Depois do codigo, liste cada vulnerabilidade corrigida com o CWE correspondente.\n\n"
    "Codigo:\n\n{codigo}"
)


def nome_seguro(modelo: str) -> str:
    return modelo.replace(":", "-").replace("/", "-")


def registrar(linha: dict) -> None:
    novo = not CSV_EXECUCOES.exists()
    with CSV_EXECUCOES.open("a", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=COLUNAS)
        if novo:
            escritor.writeheader()
        escritor.writerow(linha)


def refatorar(client, caminho: Path, modelo: str, regiao: str) -> bool:
    codigo = caminho.read_text(encoding="utf-8", errors="replace")
    try:
        resposta = client.converse(
            modelId=modelo,
            messages=[{"role": "user", "content": [{"text": PROMPT.format(codigo=codigo)}]}],
            inferenceConfig={"maxTokens": MAX_TOKENS, "temperature": 0.2},
        )
    except ClientError as erro:
        print(f"[ERRO] {caminho.name}: {erro.response['Error']['Code']} - "
              f"{erro.response['Error']['Message']}")
        return False

    texto = resposta["output"]["message"]["content"][0]["text"]
    saida = PASTA_RESULTADOS / f"{caminho.stem}__{nome_seguro(modelo)}.md"
    saida.write_text(texto, encoding="utf-8")

    uso = resposta["usage"]
    registrar({
        "data_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "arquivo": caminho.name,
        "modelo": modelo,
        "regiao": regiao,
        "tokens_entrada": uso["inputTokens"],
        "tokens_saida": uso["outputTokens"],
        "parada": resposta["stopReason"],
        "arquivo_resposta": saida.name,
    })

    aviso = "  (CORTADA: aumente MAX_TOKENS)" if resposta["stopReason"] == "max_tokens" else ""
    print(f"[OK] {caminho.name} -> {saida} | "
          f"tokens {uso['inputTokens']}/{uso['outputTokens']}{aviso}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Refatora arquivos PHP via Amazon Bedrock.")
    parser.add_argument("arquivos", nargs="+", help="um ou mais arquivos PHP")
    parser.add_argument("--modelo", default=MODELO_PADRAO, help="ID do modelo no Bedrock")
    parser.add_argument("--regiao", default=REGIAO_PADRAO, help="regiao da AWS")
    args = parser.parse_args()

    PASTA_RESULTADOS.mkdir(exist_ok=True)
    client = boto3.client("bedrock-runtime", region_name=args.regiao)

    falhas = 0
    for nome in args.arquivos:
        caminho = Path(nome)
        if not caminho.is_file():
            print(f"[ERRO] arquivo nao encontrado: {caminho}")
            falhas += 1
            continue
        if not refatorar(client, caminho, args.modelo, args.regiao):
            falhas += 1

    print(f"\nConcluido: {len(args.arquivos) - falhas} ok, {falhas} com erro. "
          f"Metricas em {CSV_EXECUCOES}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
