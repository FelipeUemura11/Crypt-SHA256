
# 🔐 SHA-256
---

## ✅ O que é SHA-256?

Principal objetivo do SHA-256: criptografa via hash, é irreversível, usado para verificação de integridade, assinaturas digitais, comparar se arquivos são iguais, etc.

SHA-256 (Secure Hash Algorithm 256 bits) é um algoritmo de **hash criptográfico** que transforma qualquer informação (como uma senha ou texto) em uma sequência **única de 64 caracteres** (256 bits) no formato hexadecimal.

---

## 🎯 Para que serve?

O SHA-256 é usado principalmente para:

- **Garantir a integridade dos dados**  
- **Verificar senhas (hashing de senha)**  
- **Segurança em blockchain (como no Bitcoin)**  
- **Assinaturas digitais**  
- **Geração de identificadores únicos**

---

## ⚙️ Como funciona?

O funcionamento do SHA-256 pode ser dividido em etapas:

1. **Pré-processamento**:
   - A mensagem é preparada e preenchida (padding) até atingir múltiplos de 512 bits.

2. **Divisão em blocos**:
   - A mensagem é separada em blocos de 512 bits.

3. **Expansão e mistura**:
   - Vários cálculos e operações bit a bit (como rotações e deslocamentos) são aplicados.
   - O hash final é gerado após 64 rodadas de operações matemáticas.

4. **Resultado final**:
   - Gera um hash único e fixo de 256 bits.

---

## 📌 Exemplo

```bash
Entrada: "felipe"
Saída:   91a0c1ff733e9e289fd6bd4762a7f64530d29a204c29b66e842d4de8711d7eb9
