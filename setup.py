from setuptools import setup, find_packages
import os
import sys

# System detection
IS_DEBIAN = os.path.exists('/etc/debian_version')
IS_ROOT = os.getuid() == 0

def get_data_files():
    """Handle systemd service file installation"""
    if IS_ROOT and os.path.exists('config/audit.service'):
        return [('/etc/systemd/system', ['config/audit.service'])]
    return []

setup(
    name="linux-hardening-audit",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "rich>=13.0.0",
    ],
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'lh-audit=linux_hardening_audit.main:main',  # Updated to full package path
        ],
    },
    data_files=get_data_files(),
    extras_require={
        'full': [
            'python-apt; platform_system=="Linux" and sys_platform=="linux"',
        ],
    },
    include_package_data=True,
    package_data={
        'benchmarks': ['*.json'],
        'docs': ['*.md'],
    },
)
