"""Test setup. The application reads its settings when it is imported, so the values the tests need
are set here first. They take priority over anything in a real backend/.env on the machine."""
import os

os.environ["SECRET_KEY"] = "t" * 48
os.environ["ENVIRONMENT"] = "development"
