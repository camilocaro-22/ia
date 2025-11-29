from fastapi import FastAPI, UploadFile, File
import pandas as pd
import joblib
import uvicorn
import tempfile
from metadata_extractor import extract_metadata

app = FastAPI()

# Load model
model = joblib.load("model.pkl")

# Column order EXACTLY as model was trained
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


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        # Extract metadata
        data = extract_metadata(tmp_path)
        if data is None:
            return {"error": "No se pudieron extraer metadatos del archivo."}

        # Convert to DataFrame
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
