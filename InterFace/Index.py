import sys
import os
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from streamlit_autorefresh import st_autorefresh
import seaborn as sns

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from idsstarly import *


# ====== Conexão ======
db = DatabaseManager()

ids = IntrusionDetectionSystem(db)

# ====== Configuração ======
st.set_page_config(page_title="IdsStarly Dashboard", layout="wide")
st.title("Análise de Logs da IdsStarly em Tempo Real")

# ===== Sidebar =====
st.sidebar.title("Configurações")
tempo_atualizacao = st.sidebar.slider('Atualizar a cada (Minutos):', 1, 60, 5)
tempo_atualizacao = tempo_atualizacao * 60
icmp_limite = ids.set_limite_icmp(st.sidebar.slider('Limite ICMP:', 10, 1000, ids.get_limite_icmp()))
syn_limite = ids.set_limite_syn(st.sidebar.slider("Limite de pacotes SYN:", 10, 1000, ids.get_limite_syn()))

st.sidebar.markdown("---")
st.sidebar.subheader("⚠️ Gerenciar Banco de Dados")

if st.sidebar.button("🗑️ Limpar Dados do Banco"):
    try:
        db.cursor.execute("DELETE FROM logs")
        db.cursor.execute("ALTER TABLE logs AUTO_INCREMENT = 1")

        db.cursor.execute("DELETE FROM blacklist")
        db.cursor.execute("ALTER TABLE blacklist AUTO_INCREMENT = 1")

        db.conn.commit()

        st.sidebar.success("✅ Dados apagados com sucesso!")
    except Exception as e:
        st.sidebar.error(f"❌ Erro: {e}")
# ===== AutoRefresh =====
st_autorefresh(interval=tempo_atualizacao * 1000, key="autorefresh")

# ===== Funções =====
@st.cache_data(ttl=tempo_atualizacao)
def carregar_dados_agrupados():
    db.cursor.execute("SELECT label, COUNT(*) FROM logs GROUP BY label")
    dados = db.cursor.fetchall()
    df = pd.DataFrame(dados, columns=['Label', 'Quantidade'])
    return df


@st.cache_data(ttl=tempo_atualizacao)
def carregar_logs_completos():
    query = "SELECT timestamp, src_ip, src_port, dst_ip, dst_port, label, descricao FROM logs ORDER BY id DESC"
    db.cursor.execute(query)
    dados = db.cursor.fetchall()
    df = pd.DataFrame(dados, columns=[
        'Timestamp', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Label', 'Descrição'
    ])
    return df


@st.cache_data(ttl=tempo_atualizacao)
def carregar_blacklist():
    query = "SELECT * FROM blacklist"
    db.cursor.execute(query)
    dados = db.cursor.fetchall()
    df = pd.DataFrame(dados, columns=[
        'id', 'timestamp', 'ip', 'descricao'
    ])
    return df

@st.cache_data(ttl=tempo_atualizacao)
def top_ips_origem():
    query = '''
        SELECT src_ip, COUNT(*) 
        FROM logs 
        GROUP BY src_ip 
        ORDER BY COUNT(*) DESC 
        LIMIT 10
    '''
    db.cursor.execute(query)
    dados = db.cursor.fetchall()
    df = pd.DataFrame(dados, columns=['IP', 'Quantidade'])
    return df


@st.cache_data(ttl=tempo_atualizacao)
def heatmap_comunicacao():
    query = '''
        SELECT src_ip, dst_ip, COUNT(*) 
        FROM logs 
        GROUP BY src_ip, dst_ip
    '''
    db.cursor.execute(query)
    dados = db.cursor.fetchall()
    df = pd.DataFrame(dados, columns=['Src IP', 'Dst IP', 'Quantidade'])
    return df


@st.cache_data(ttl=tempo_atualizacao)
def distribuicao_portas():
    query = '''
        SELECT dst_port, COUNT(*) 
        FROM logs 
        WHERE dst_port != 'N/A'
        GROUP BY dst_port 
        ORDER BY COUNT(*) DESC 
        LIMIT 20
    '''
    db.cursor.execute(query)
    dados = db.cursor.fetchall()
    df = pd.DataFrame(dados, columns=['Porta', 'Quantidade'])
    return df


# ===== Abas =====
aba_grafico, aba_logs, aba_blacklist = st.tabs(["📊 Gráfico de Tráfego", "📄 Logs Completos", "🚫 BlackList"])

# ===== Aba Gráfico =====
with aba_grafico:
    df = carregar_dados_agrupados()

    st.subheader("Tráfego da rede")

    fig, ax = plt.subplots()

    cores = plt.cm.Paired.colors

    wedges, texts = ax.pie(
        df['Quantidade'],
        startangle=90,
        colors=cores,
        wedgeprops=dict(width=0.5)
    )

    total = df['Quantidade'].sum()
    labels = [
        f"{label} - {quantidade} ({quantidade/total:.1%})"
        for label, quantidade in zip(df['Label'], df['Quantidade'])
    ]

    ax.legend(
        wedges,
        labels,
        title="Categorias",
        loc="center left",
        bbox_to_anchor=(1, 0.5)
    )

    ax.axis('equal')
    st.pyplot(fig)
    
    
    st.subheader("IPs de Origem Mais Ativos")

    df_ip = top_ips_origem()

    st.bar_chart(df_ip.set_index('IP'))

    st.info(f"Atualiza a cada {tempo_atualizacao} segundos automaticamente.")
    
    
    st.subheader("Heatmap de Comunicação IP → IP")

    df_heat = heatmap_comunicacao()

    if not df_heat.empty:
        pivot = df_heat.pivot(index="Src IP", columns="Dst IP", values="Quantidade").fillna(0)

        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(pivot, cmap="Reds", ax=ax)
        plt.title("Volume de Comunicação entre IPs")
        st.pyplot(fig)
    else:
        st.warning("Sem dados suficientes para gerar o heatmap.")
    
    
    st.subheader("Distribuição de Portas de Destino")

    df_portas = distribuicao_portas()

    st.bar_chart(df_portas.set_index('Porta'))
    
    
# ===== Aba Logs =====
with aba_logs:
    st.subheader("Logs Completos da IDS")

    logs_df = carregar_logs_completos()

    num_linhas = st.slider(
        "Quantidade de linhas para exibir:",
        min_value=10,
        max_value=max(10, len(logs_df)),
        value=50,
        step=10
    )

    st.dataframe(logs_df.head(num_linhas), use_container_width=True)

    st.info(f"Mostrando as {num_linhas} linhas mais recentes dos logs.")


# ===== Aba Blacklist =====
with aba_blacklist:
    st.subheader("Blacklist")

    blacklist_df = carregar_blacklist()

    if len(blacklist_df) != 0:
        num_linhas = st.slider(
            "🔢 Quantidade de linhas para exibir:",
            min_value=10,
            max_value=max(10, len(blacklist_df)),
            value=50,
            step=10
        )

        st.dataframe(blacklist_df.head(num_linhas), use_container_width=True)

        st.info(f"Mostrando as {num_linhas} linhas da blacklist.")
    else:
        st.subheader("🚫 Sem dados na Blacklist")
