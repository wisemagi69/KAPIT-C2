"""Run this project's wrapper using explicit local JDK/SDK/cache paths only."""
from pathlib import Path
import argparse
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", action="store_true", help="Use verified local distribution to create wrapper")
    parser.add_argument("--java-home", default=os.environ.get("KAPIT_JAVA_HOME", r"C:\Program Files\Android\Android Studio\jbr"))
    parser.add_argument("--sdk", default=os.environ.get("KAPIT_ANDROID_SDK", str(Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk")))
    args, tasks = parser.parse_known_args()
    java = Path(args.java_home).resolve()
    sdk = Path(args.sdk).resolve()
    if not (java / "bin" / "java.exe").is_file() or not (sdk / "platforms" / "android-36" / "android.jar").is_file():
        raise SystemExit("Compatible JDK and existing API36 SDK required; no global installation is performed")
    env = os.environ.copy()
    env.update(JAVA_HOME=str(java), ANDROID_HOME=str(sdk), ANDROID_SDK_ROOT=str(sdk),
               GRADLE_USER_HOME=str(ROOT / ".gradle-user-home"),
               ANDROID_USER_HOME=str(ROOT / ".android-user-home"))
    env.pop("ANDROID_SDK_HOME", None)  # Deprecated variable appends .android and conflicts with USER_HOME.
    executable = ROOT / ".tooling" / "gradle-8.13" / "bin" / "gradle.bat" if args.bootstrap else ROOT / "gradlew.bat"
    if not executable.is_file():
        raise SystemExit("Run bootstrap_gradle.py and wrapper generation first")
    # A list is passed directly; no project text is interpolated into shell commands.
    result = subprocess.run([str(executable), "--no-daemon", "--console=plain", *tasks], cwd=ROOT, env=env)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
