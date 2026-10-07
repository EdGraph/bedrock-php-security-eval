# Avaliação de correções de segurança geradas por LLMs no Amazon Bedrock

Experimento que envia arquivos PHP com vulnerabilidades conhecidas para modelos do **Amazon Bedrock** e verifica, lendo o código gerado, se as correções realmente funcionam, em vez de confiar na explicação que o próprio modelo dá.

Complementa meu TCC na PUCPR, que analisa o uso de LLMs na mitigação de vulnerabilidades em código legado PHP.

## Por que isso importa

Um modelo pode devolver um relatório convincente, com CWEs e explicações, enquanto o código entregue faz outra coisa. A pergunta deste experimento é simples: **o que o modelo diz que corrigiu bate com o que ele de fato corrigiu?**

## Como funciona

1. `refatorar_bedrock.py` lê um ou mais arquivos PHP e chama o modelo pela API `Converse` do Bedrock (boto3), pedindo o arquivo completo corrigido e a lista de CWEs.
2. Cada resposta é salva em `resultados/`, e as métricas da chamada (modelo, região, tokens, motivo de parada) vão para `resultados/execucoes.csv`.
3. A avaliação é **manual**: leio o código gerado e classifico cada pilar com a régua abaixo.

Trocar de modelo é só mudar o `--modelo`, o que permite comparar modelos menores e maiores no mesmo arquivo, avaliando qualidade e custo.

### Régua de avaliação

| Nota | Significado |
|------|-------------|
| 0 | Seguro: a vulnerabilidade foi corrigida com a prática recomendada |
| 1 | Prática frágil: mitigado, mas de forma frágil ou com problema secundário |
| 2 | Vulnerável: falha crítica continua explorável |

## Resultados

| Arquivo | Pilar | Modelo | Tokens (entrada/saída) | O que o modelo disse | O que o código mostra | Nota |
|---------|-------|--------|------------------------|----------------------|-----------------------|------|
| search.php | Integridade | Amazon Nova Lite | 1753 / 2741 | "Adicionado uso de parâmetros" contra SQL Injection | Usou `mysqli_real_escape_string`, não prepared statement; XSS corrigido; erro do banco ainda vaza via `die(mysqli_error())` | 1 |
| _a preencher_ | | | | | | |

### Caso em destaque: `search.php` com Amazon Nova Lite

O arquivo original tinha SQL Injection numa busca com `LIKE`, XSS no campo de busca e uma validação que redirecionava sem `exit()`, ou seja, o script continuava executando depois do redirecionamento.

O que o modelo acertou:
- Escapou a saída do campo de busca com `htmlspecialchars` (XSS corrigido).
- Adicionou `exit()` após o redirecionamento, o que fez a validação passar a funcionar de verdade.

Onde o relatório do modelo não bateu com o código:
- Afirmou ter usado **parâmetros** contra SQL Injection, mas usou **escape manual** (`mysqli_real_escape_string`). Isso mitiga a injeção, mas é mais frágil que prepared statement, porque depende do charset da conexão e de ninguém esquecer o escape em outra query.
- O trecho "corrigido" mostrado no relatório não continha a linha de escape que estava no código.
- Classificou CWEs de forma incorreta: usou CWE-476 (*NULL Pointer Dereference*) para "função obsoleta" (o adequado seria CWE-477) e CWE-652 (*XQuery Injection*) para a falta de `exit()` após redirecionamento (o adequado seria CWE-698).
- Tratou como correção a troca de `location` por `Location` no cabeçalho, que não tem efeito, porque cabeçalhos HTTP não diferenciam maiúsculas.
- Não tratou o vazamento de erro do banco (CWE-209).

**Conclusão:** a saída de um LLM precisa ser verificada no código, não no relatório que o acompanha.

## Como executar

Pré-requisitos: conta AWS com acesso ao Bedrock e Python 3 com `boto3`. O jeito mais simples é rodar no **AWS CloudShell**, que já vem autenticado e com boto3 instalado, sem precisar de chaves de acesso.

```bash
# um arquivo, modelo e região padrão
python3 refatorar_bedrock.py amostras/search.php

# vários arquivos, outro modelo
python3 refatorar_bedrock.py amostras/*.php --modelo us.amazon.nova-pro-v1:0

# outra região
python3 refatorar_bedrock.py amostras/search.php --regiao us-east-1
```

O ID de cada modelo está no catálogo do Bedrock no console. Alguns modelos exigem o ID com prefixo de região (por exemplo, `us.`), chamado de perfil de inferência.

## Estrutura

```
.
├── refatorar_bedrock.py   # chama o Bedrock e registra as métricas
├── requirements.txt
├── amostras/              # arquivos PHP vulneráveis usados nos testes
└── resultados/            # respostas dos modelos e execucoes.csv
```

## Aviso

Os arquivos em `amostras/` são **propositalmente vulneráveis** e vêm de projetos usados na pesquisa do TCC. Não use esse código em produção.

## Próximos passos

- Testar um arquivo de cada pilar (confidencialidade, integridade, disponibilidade).
- Comparar um modelo pequeno com um maior no mesmo arquivo, avaliando qualidade e custo em tokens.
- Rodar o script em um pipeline de CI (GitHub Actions).
