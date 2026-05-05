#!/bin/bash
echo ""
echo "============================================================"
echo "🛡️  AI Cyber Defense Platform v2.0 — Starting..."
echo "============================================================"
pip install fastapi uvicorn python-multipart scikit-learn numpy aiofiles -q 2>/dev/null
echo "✅ Dependencies installed"
echo "🌐 Opening: http://localhost:8000"
echo "👤 Login: admin / admin123  OR  analyst / analyst123"
echo "📖 API Docs: http://localhost:8000/docs"
echo "============================================================"
python3 backend.py
