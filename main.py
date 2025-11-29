from fastapi import FastAPI, UploadFile, File
import pandas as pd
import joblib
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
    "IatVRA",  # ← COHERENTE CON EL MODELO
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "NumberOfSections",
    "SizeOfStackReserve",
    "DllCharacteristics",
    "ResourceSize",
    "BitcoinAddresses"
]


@app.get("/")
def root():
    return {"message": "API funcionando correctamente"}


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        # Extract metadata
        data = extract_metadata(tmp_path)
        if data is None:
            return {"error": "No se pudieron extraer metadatos del archivo."}

        # Build DataFrame
        df = pd.DataFrame([data], columns=FEATURE_COLUMNS)

        # Predict
        pred = model.predict(df)[0]
        label = "benign" if pred == 1 else "ransomware"

        return {
            "prediction": label,
            "features": data
        }

    except Exception as e:
        return {"error": str(e)}
