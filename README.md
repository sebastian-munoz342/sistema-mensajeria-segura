# Sistema de Mensajería Segura - IPSS U1

**Evaluación Sumativa Unidad 1 – COMPLETADA**  
**Instituto Profesional San Sebastián**  
**Ingeniería en Ciberseguridad - 2° año**

---

## Estado: **TERMINADO**  
**Cumple al 100% RA1 y RA2**  
**Abierto a mejoras, colaboraciones e ideas**

---

## Resultados de Aprendizaje Cumplidos

### RA1: Conceptos básicos de criptografía
- [Checkmark] Confidencialidad, integridad y autenticación aplicadas  
- [Checkmark] Protección efectiva de datos sensibles  
- [Checkmark] Validación de autenticación en información protegida  

### RA2: Algoritmos de cifrado
- [Checkmark] **3 simétricos**: DES, AES-256, Blowfish  
- [Checkmark] **3 asimétricos**: RSA, ECC, ElGamal  
- [Checkmark] Funciones hash: SHA-256, MD5  
- [Checkmark] Protocolos: Diffie-Hellman (intercambio de claves)

---

## Algoritmos Implementados

| Tipo        | Algoritmo   | Librería         |
|-------------|-------------|------------------|
| Simétrico   | DES         | `pycryptodome`   |
| Simétrico   | AES-256     | `pycryptodome`   |
| Simétrico   | Blowfish    | `pycryptodome`   |
| Asimétrico  | RSA         | `cryptography`   |
| Asimétrico  | ECC         | `cryptography`   |
| Asimétrico  | ElGamal     | `sympy`          |

---

## Funcionalidades Completadas
- [Checkmark] Cifrado/decifrado de mensajes  
- [Checkmark] Menú interactivo  
- [Checkmark] Lectura/escritura en archivos `.txt`  
- [Checkmark] Validación de entrada y manejo de errores  

---

## Requisitos
```bash
pip install pycryptodome cryptography sympy
