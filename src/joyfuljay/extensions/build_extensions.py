#!/usr/bin/env python3
"""Build script for Cython extensions.

Run this script to compile the Cython extensions for better performance:

    python -m joyfuljay.extensions.build_extensions

Or from the project root:

    python src/joyfuljay/extensions/build_extensions.py

Requirements:
    pip install cython numpy

After building, restart Python to use the compiled extensions.
"""

import os
import sys
from pathlib import Path


def build_extensions():
    """Build Cython extensions in-place."""
    try:
        from Cython.Build import cythonize
        import numpy as np
    except ImportError as e:
        print(f"Error: {e}")
        print("\nPlease install build dependencies:")
        print("    pip install cython numpy")
        return 1

    from setuptools import Extension, setup
    from setuptools.dist import Distribution

    # Get the extensions directory
    ext_dir = Path(__file__).parent.resolve()

    print(f"Building extensions in: {ext_dir}")

    # Build directly in the extensions directory
    os.chdir(ext_dir)

    # Define extensions with simple names (built in current directory)
    extensions = [
        Extension(
            "_fast_stats",
            sources=["_fast_stats.pyx"],
            include_dirs=[np.get_include()],
            define_macros=[("NPY_NO_DEPRECATED_API", "NPY_1_7_API_VERSION")],
        ),
        Extension(
            "_fast_entropy",
            sources=["_fast_entropy.pyx"],
            include_dirs=[np.get_include()],
            define_macros=[("NPY_NO_DEPRECATED_API", "NPY_1_7_API_VERSION")],
        ),
    ]

    # Cythonize with optimizations
    ext_modules = cythonize(
        extensions,
        compiler_directives={
            "language_level": 3,
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
            "initializedcheck": False,
        },
        annotate=True,  # Generate HTML annotation files
    )

    dist = Distribution({
        "name": "joyfuljay-extensions",
        "ext_modules": ext_modules,
    })

    # Run build_ext
    cmd = dist.get_command_obj("build_ext")
    cmd.inplace = True
    cmd.ensure_finalized()
    cmd.run()

    print("\n✓ Extensions built successfully!")
    print("  Restart Python to use the compiled extensions.")

    # Check what was built
    built = []
    for ext in ext_modules:
        name = ext.name.split(".")[-1]
        for suffix in [".cpython-*.so", ".cpython-*.pyd", ".so", ".pyd"]:
            import glob
            matches = glob.glob(str(ext_dir / f"{name}{suffix}"))
            if matches:
                built.extend(matches)

    if built:
        print("\n  Built files:")
        for f in built:
            print(f"    - {Path(f).name}")

    return 0


if __name__ == "__main__":
    sys.exit(build_extensions())
