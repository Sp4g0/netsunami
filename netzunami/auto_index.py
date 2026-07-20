import os
import json
import glob
from pathlib import Path
from datetime import datetime

from .config import Config
from .embedder import embed


def auto_index(
    data_dir: str | None = None,
    model_name: str = "all-MiniLM-L6-v2",
    verbose: bool = True,
):
    cfg = Config.load()
    data_dir = data_dir or cfg.data_dir
    base = Path(data_dir)

    knowledge_dir = base / "knowledge"
    knowledge_dir.mkdir(parents=True, exist_ok=True)
    meta_path = knowledge_dir / "metadata.json"

    sources = {
        "configs": base / "configs",
        "sessions": base / "sessions",
        "manuals": knowledge_dir / "manuals",
    }

    all_texts = []
    all_meta = []
    new_files = []

    for label, src_dir in sources.items():
        if not src_dir.exists():
            continue
        for fpath in sorted(src_dir.iterdir()):
            if not fpath.is_file():
                continue
            fname = fpath.name
            if "_emb" in fname:
                continue
            if fpath.suffix.lower() not in (".cfg", ".txt", ".log", ".pdf"):
                continue
            new_files.append((label, fpath))

    if not new_files:
        if verbose:
            print(f"  Auto-index: nessun nuovo file")
        return

    if verbose:
        print(f"  Auto-index: {len(new_files)} nuovi file...")

    for label, fpath in new_files:
        try:
            if fpath.suffix.lower() == ".pdf":
                import fitz
                doc = fitz.open(str(fpath))
                raw = ""
                for page in doc:
                    raw += page.get_text()
                doc.close()
            else:
                raw = fpath.read_text(encoding="utf-8", errors="replace")

            lines = [l for l in raw.splitlines() if l.strip()]
            for i in range(0, len(lines), 20):
                chunk = "\n".join(lines[i : i + 20])
                all_texts.append(chunk)
                all_meta.append({
                    "source": f"{label}/{fpath.name}",
                    "chunk": i // 20,
                    "text": chunk[:200],
                    "date": datetime.now().isoformat(),
                })

            emb_name = fpath.stem + "_emb" + fpath.suffix
            fpath.rename(fpath.with_name(emb_name))
            if verbose:
                nchunks = (len(lines) // 20) + (1 if len(lines) % 20 else 0)
                print(f"    {fpath.name} → _emb ({nchunks} chunk)")

        except Exception as e:
            if verbose:
                print(f"    ✗ {fpath.name}: {e}")

    if not all_texts:
        return

    # Carica metadati esistenti e recupera testi per re-indicizzazione completa
    existing_texts = []
    if meta_path.exists():
        with open(meta_path) as f:
            existing_meta = json.load(f)
        for m in existing_meta:
            if m.get("text"):
                existing_texts.append(m["text"])
    else:
        existing_meta = []

    all_texts = existing_texts + all_texts
    all_meta_list = existing_meta + all_meta

    vectors = embed(all_texts, model_name)
    import numpy as np
    import faiss

    dim = vectors.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(vectors.astype(np.float32))

    faiss.write_index(index, str(knowledge_dir / "faiss.index"))
    with open(meta_path, "w") as f:
        json.dump(all_meta_list, f, indent=2)

    if verbose:
        print(f"  Knowledge base: {index.ntotal} vettori")
