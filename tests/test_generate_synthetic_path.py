from pathlib import Path

from synthetic_data.generate_synthetic import default_output_dir


def test_generator_output_directory_is_relative_to_script():
    assert default_output_dir() == Path(__file__).resolve().parents[1] / "synthetic_data"
