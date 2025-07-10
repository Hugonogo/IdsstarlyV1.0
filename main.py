from idsstarly import *

# ====== Conexão ======
db = DatabaseManager()


ids = IntrusionDetectionSystem(db)
ids.iniciar_monitoramento("wlo1")