# PyInstaller build for the installed app:  .venv\Scripts\pyinstaller packaging\PhishGuard.spec
#
# Two programs in one folder:
#   PhishGuard.exe        what Windows runs for every clicked link, plus the dashboard window.
#                         Standard library + pywebview only, so a click on a trusted link stays fast.
#   PhishGuardEngine.exe  the engine (web server, sandbox, AI Guard), started only when a link needs checking.
# The model-training code and its libraries (torch, transformers, pandas) are left out: at run time
# the AI Guard is a small scikit-learn model.
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
PG = ROOT / "phishguard"
ICON = str(ROOT / "packaging" / "phishguard.ico")
VERSION = str(ROOT / "packaging" / "version.txt")
PATHS = [str(ROOT), str(ROOT / "launcher")]
NEVER = ["torch", "transformers", "tokenizers", "pandas", "matplotlib", "pytest", "IPython", "jupyter", "notebook",
         "tkinter", "sympy", "PyQt5", "PyQt6", "PySide2", "PySide6", "pyarrow", "PIL", "polars",
         "sklearn.datasets", "scipy.datasets"]

# --- PhishGuard.exe ------------------------------------------------------------------------------
app = Analysis(
    [str(ROOT / "launcher" / "appmain.py")],
    pathex=PATHS,
    hiddenimports=["pglaunch", "registry"],
    excludes=NEVER + ["phishguard", "flask", "werkzeug", "waitress", "playwright", "sklearn", "scipy", "numpy",
                      "joblib", "tldextract", "requests", "run"],
)
app_exe = EXE(PYZ(app.pure), app.scripts, [], exclude_binaries=True, name="PhishGuard", console=False,
              icon=ICON, version=VERSION)

# --- PhishGuardEngine.exe ---------------------------------------------------------------------------
datas = [
    (str(PG / "templates"), "phishguard/templates"),
    (str(PG / "static"), "phishguard/static"),
    (str(PG / "data"), "phishguard/data"),
    (str(PG / "hooks.js"), "phishguard"),
    (str(PG / "guard" / "model.joblib"), "phishguard/guard"),
    (str(PG / "guard" / "data"), "phishguard/guard/data"),
] + collect_data_files("tldextract")

# The AI Guard model is loaded from a file, so PyInstaller cannot see which scikit-learn parts it needs.
hidden = ["run", "registry", "sklearn.pipeline", "sklearn.linear_model", "sklearn.feature_extraction.text",
          "sklearn.preprocessing"] + collect_submodules(
    "phishguard", filter=lambda name: name not in ("phishguard.guard.train", "phishguard.guard.distil"))

engine = Analysis(
    [str(ROOT / "launcher" / "enginemain.py")],
    pathex=PATHS,
    datas=datas,
    hiddenimports=hidden,
    excludes=NEVER + ["webview", "clr", "pythonnet", "clr_loader"],
)
engine_exe = EXE(PYZ(engine.pure), engine.scripts, [], exclude_binaries=True, name="PhishGuardEngine",
                 console=False, icon=ICON, version=VERSION)

coll = COLLECT(app_exe, app.binaries, app.datas, engine_exe, engine.binaries, engine.datas, name="PhishGuard")
