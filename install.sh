#!/bin/bash
# NORHACK Setup Script for WSL2/Linux

echo "Installing dependencies..."
pip install -r requirements.txt

# Create session directory
mkdir -p sessions

# Setup alias (optional)
echo "Adding 'hack' alias to ~/.bashrc..."
ALIAS_LINE="alias hack='python3 $(pwd)/hack.py'"
if ! grep -q "$ALIAS_LINE" ~/.bashrc; then
    echo "$ALIAS_LINE" >> ~/.bashrc
    echo "Alias added. Restart your shell or run 'source ~/.bashrc'."
else
    echo "Alias already exists."
fi

echo "Setup complete."
