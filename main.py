from fastapi import FastAPI, UploadFile, File
import pandas as pd
import joblib
import uvicorn
import tempfile
from metadata_extractor import extract_metadata

app = FastAPI()

# Load model
model = joblib.load("model.pkl")

FEATURE_COLUMNS = [
    "Machine",
    "DebugSize",
    "DebugRVA",
    "MajorImageVersion",
    "MajorOSVersion",
    "ExportRVA",
    "ExportSize",
    "IatRVA",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "NumberOfSections",
    "SizeOfStackReserve",
    "DllCharacteristics",
    "ResourceSize",
    "BitcoinAddresses"
]

# 🔥 ESTA ES LA RUTA QUE DEBES AGREGAR 🔥


@app.get("/")
def root():
    return {"message": "API funcionando correctamente"}


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        data = extract_metadata(tmp_path)
        if data is None:
            return {"error": "No se pudieron extraer metadatos del archivo."}

        df = pd.DataFrame([data], columns=FEATURE_COLUMNS)

        pred = model.predict(df)[0]
        label = "benign" if pred == 1 else "ransomware"

        return {
            "prediction": label,
            "features": data
        }

    except Exception as e:
        return {"error": str(e)}
