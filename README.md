# Deteccion_de-Ransomware_en_Archivos_Ejecutables_de_Windows

## Despliegue en Render

1. Crear nuevo servicio Web Service
2. Elegir "Deploy from GitHub"
3. Seleccionar este repositorio
4. Configurar:

Runtime = Python 3  
Build Command = pip install -r requirements.txt  
Start Command = uvicorn main:app --host 0.0.0.0 --port 10000  

5. Subir model.pkl al repo antes del deploy

