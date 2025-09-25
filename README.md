# 🛡️ IDS Starly – Sistema de Detecção de Intrusão em Python

Este projeto é um **Sistema Simples de Detecção de Intrusão (IDS)** desenvolvido em **Python**, utilizando a biblioteca **Scapy** para captura e análise de pacotes de rede em tempo real.  
Os eventos detectados são armazenados em um **banco de dados MySQL** e podem ser visualizados em um **dashboard interativo** feito com **Streamlit**.

---

## 📌 Funcionalidades
- Captura e análise de pacotes de rede em tempo real.
- Detecção de padrões de ataque como:
  - **SYN Flood**
  - **ICMP Flood**
  - **Port Scan**
  - **Fragmentation Attack**
  - **Slowloris / Slow HTTP**
  - **NMAP Scan**
- Identificação de **assinaturas maliciosas** no tráfego.
- Armazenamento dos logs em banco MySQL.
- **Blacklist automática** de IPs suspeitos.
- Dashboard interativo para monitoramento:
  - Gráficos de tráfego
  - Heatmap de comunicação IP → IP
  - Distribuição de portas
  - Lista de IPs bloqueados

---

## ⚙️ Requisitos

Antes de rodar o projeto, você precisará instalar:

- Python 3.9+
- [MySQL Server](https://dev.mysql.com/downloads/mysql/)
- Bibliotecas Python:
  ```bash
  pip install scapy streamlit pandas matplotlib seaborn mysql-connector-python streamlit-autorefresh

---
## Configuração do Banco de Dados (MySQL)

Acesse o MySQL com seu usuário root:
```bash
mysql -u root -p
```

Crie o banco de dados:
```bash
CREATE DATABASE idsstarlyDB;
```

Crie um usuário e dê permissões:
```bash
CREATE USER 'admin'@'localhost' IDENTIFIED BY 'admin';
GRANT ALL PRIVILEGES ON idsstarlyDB.* TO 'admin'@'localhost';
FLUSH PRIVILEGES;
```


As tabelas necessárias (logs e blacklist) serão criadas automaticamente na primeira execução do programa.


---
## Como Rodar
🔹 1. Rodar o IDS no terminal

O arquivo main.py inicia a captura de pacotes e a análise em tempo real.
Basta executar:
```bash
sudo python3 main.py
```

🔹 2. Rodar o Dashboard (Interface Web)

O arquivo Index.py inicia a interface de monitoramento com Streamlit.
Execute:

```bash

streamlit run InterFace/Index.py

```
