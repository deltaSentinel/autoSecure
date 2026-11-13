import pathlib

ROOT = pathlib.Path(__file__).parents[1]

def test_train_dir_has_no_deployment_artifacts():
    for name in ("model.joblib", "feature_keys.json"):
        assert not (ROOT / "train" / name).exists(), (
            "deployment artifacts must live only in models/ — train.py should "
            "be invoked with --out ../models")

def test_agent_model_path_points_at_models():
    src = (ROOT / "agent" / "main.py").read_text()
    assert '"models", "model.joblib"' in src
    assert '"train", "model.joblib"' not in src
