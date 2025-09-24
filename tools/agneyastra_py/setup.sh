#!/bin/bash

# Agneyastra Python Setup Script
# This script sets up the Python environment for running Agneyastra

echo "Setting up Agneyastra Python environment..."
# Check if Python 3.8+ is available
if ! python3 --version | grep -E "3\.(8|9|10|11|12)" > /dev/null; then
    echo "Error: Python 3.8 or higher is required"
    exit 1
fi

echo "Python version check passed"

# Create virtual environment if it doesn't exist
#if [ ! -d "venv" ]; then
#    echo "Creating virtual environment..."
#    python3 -m venv venv
#fi

# Activate virtual environment
#echo "Activating virtual environment..."
#source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip3 install --upgrade pip

# Install requirements
echo "Installing Python dependencies..."
{
    pip3 install -r $PWD/requirements.txt
} || {
    pip3 install -r $PWD/agneyastra_py/requirements.txt
}

# Create config directory if it doesn't exist
echo "Setting up configuration directory..."
