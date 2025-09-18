# DES - Data Encryption Standard (Implementação em Python)

Este projeto contém uma implementação do algoritmo de criptografia simétrica **DES (Data Encryption Standard)** em Python.  

## 🔑 Sobre o algoritmo DES

O DES usa a mesma chave para cifrar e decifrar. O processo de criptografia, de forma simplificada, é o seguinte:

1. **Divisão em blocos:** a mensagem é quebrada em blocos de 64 bits (8 bytes).  
2. **Padding:** se o último bloco não tiver 8 bytes, acrescentamos bytes de preenchimento para completar.  
3. **Permutação inicial:** cada bloco passa por uma permutação fixa que reorganiza os bits.  
4. **Rede de Feistel:** cada bloco é dividido em duas metades (L e R). Em cada rodada:
   - A metade direita é expandida e combinada com uma **subchave** derivada da chave principal.
   - O resultado passa por S-boxes (substituições) e uma permutação (P).
   - O resultado é então XORado com a metade esquerda; as metades são trocadas.
   - As subchaves mudam a cada rodada (agendamento de chaves).
5. **Permutação final:** após 16 rodadas as metades são recombinadas e uma última permutação reordena os bits, produzindo o bloco cifrado.
6. **Modo de operação:** cada bloco é cifrado independentemente; o resultado final é a concatenação dos blocos cifrados.

Para decifrar, o processo é o mesmo, porém as subchaves são usadas na ordem inversa — isso recupera o bloco original e, por fim, o padding é removido.

## 📦 Como executar

1. Clone ou copie os arquivos para sua máquina.  
2. Execute no terminal:

```bash
python main.py
