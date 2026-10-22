"""Train all models from the command line:  python -m app.ml.train"""
import json
import time

from .. import config
from .models import ModelRegistry


def main() -> None:
    config.ensure_dirs()
    t0 = time.time()
    metrics = ModelRegistry().train_all()
    print(json.dumps(metrics, indent=2))
    print(f"\nTrained 5 models in {time.time() - t0:.1f}s -> {config.MODEL_DIR}")


if __name__ == "__main__":
    main()
