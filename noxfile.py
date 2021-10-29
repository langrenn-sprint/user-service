"""Nox sessions."""
import tempfile

import nox
from nox.sessions import Session
import nox_poetry

package = "user_service"
locations = "src", "tests", "noxfile.py"
nox.options.stop_on_first_error = True
nox.options.sessions = (
    "lint",
    "mypy",
    "pytype",
    "unit_tests",
    "integration_tests",
    "contract_tests",
)


@nox_poetry.session
def unit_tests(session: Session) -> None:
    """Run the unit test suite."""
    args = session.posargs
    session.install(
        ".",
        "pytest",
        "pytest-mock",
        "pytest-aiohttp",
        "requests",
    )
    session.run(
        "pytest",
        "-m unit",
        "-rA",
        *args,
        env={"CONFIG": "test", "JWT_SECRET": "secret"},
    )


@nox_poetry.session
def integration_tests(session: Session) -> None:
    """Run the integration test suite."""
    args = session.posargs or ["--cov"]
    session.install(
        ".",
        "coverage[toml]",
        "pytest",
        "pytest-cov",
        "pytest-mock",
        "pytest-aiohttp",
        "requests",
    )
    session.run(
        "pytest",
        "-m integration",
        "-rA",
        *args,
        env={
            "CONFIG": "test",
            "JWT_SECRET": "secret",
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "password",
        },
    )


@nox_poetry.session
def contract_tests(session: Session) -> None:
    """Run the contract test suite."""
    args = session.posargs
    session.install(
        ".",
        "pytest",
        "pytest-docker",
        "pytest_mock",
        "pytest-asyncio",
        "requests",
    )
    session.run(
        "pytest",
        "-m contract",
        "-rA",
        *args,
        env={
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "password",
            "JWT_EXP_DELTA_SECONDS": "60",
            "DB_USER": "admin",
            "DB_PASSWORD": "admin",
            "LOGGING_LEVEL": "DEBUG",
        },
    )


@nox_poetry.session
def black(session: Session) -> None:
    """Run black code formatter."""
    args = session.posargs or locations
    session.install("black")
    session.run("black", *args)


@nox_poetry.session
def lint(session: Session) -> None:
    """Lint using flake8."""
    args = session.posargs or locations
    session.install(
        "flake8",
        "flake8-annotations",
        "flake8-bandit",
        "flake8-black",
        "flake8-bugbear",
        "flake8-docstrings",
        "flake8-import-order",
        "darglint",
        "flake8-assertive",
    )
    session.run("flake8", *args)


@nox_poetry.session
def safety(session: Session) -> None:
    """Scan dependencies for insecure packages."""
    with tempfile.NamedTemporaryFile() as requirements:
        session.run(
            "poetry",
            "export",
            "--dev",
            "--format=requirements.txt",
            "--without-hashes",
            f"--output={requirements.name}",
            external=True,
        )
        session.install("safety")
        session.run("safety", "check", f"--file={requirements.name}", "--full-report")


@nox_poetry.session
def mypy(session: Session) -> None:
    """Type-check using mypy."""
    args = session.posargs or locations
    session.install("mypy")
    session.run("mypy", *args)


@nox_poetry.session
def pytype(session: Session) -> None:
    """Run the static type checker using pytype."""
    args = session.posargs or ["--disable=import-error", *locations]
    session.install("pytype")
    session.run("pytype", *args)


@nox_poetry.session
def xdoctest(session: Session) -> None:
    """Run examples with xdoctest."""
    args = session.posargs or ["all"]
    session.install(".", "xdoctest")
    session.run("python", "-m", "xdoctest", package, *args)


@nox_poetry.session
def docs(session: Session) -> None:
    """Build the documentation."""
    session.install(".", "sphinx", "sphinx_autodoc_typehints")
    session.run("sphinx-build", "docs", "docs/_build")


@nox_poetry.session
def coverage(session: Session) -> None:
    """Upload coverage data."""
    session.install("coverage[toml]", "codecov")
    session.run("coverage", "xml", "--fail-under=0")
    session.run("codecov", *session.posargs)
