# Lobster Graphic Calculator

A fully graphical calculator application for macOS written in the [Lobster](https://github.com/aardappel/lobster) programming language.

This directory is intentionally separate from the ApexMail mail platform. It is a small, whimsical proof-of-concept app kept in the repository to experiment with the Lobster language and a native-style graphical UI.

## Features

- **Fully Graphical Interface**: Clean, modern UI with buttons and display
- **Basic Arithmetic**: Addition, subtraction, multiplication, division
- **Decimal Support**: Enter decimal numbers with decimal point
- **Sign Toggle**: Change positive numbers to negative and vice versa
- **Backspace**: Delete the last entered digit
- **Clear**: Reset the calculator completely
- **Division by Zero Handling**: Shows error message
- **Hover Effects**: Visual feedback when hovering over buttons
- **Press Effects**: Visual feedback when pressing buttons
- **Keyboard Quit**: Press Escape to close the app

## Prerequisites

Before running, you need Lobster installed on your system.

### Installing Lobster

**Using Homebrew** (recommended for macOS):
```bash
brew install lobster-lang
```

**Building from source**:
```bash
git clone https://github.com/aardappel/lobster.git
cd lobster
# Follow build instructions in the repository
```

**Pre-built binaries**:
Download from the [Lobster releases page](https://github.com/aardappel/lobster/releases)

## Running the Calculator

```bash
cd Lobster
lobster main.lob
```

## Calculator Layout

| Button | Function |
|--------|----------|
| C | Clear all values |
| ± | Toggle positive/negative |
| ⌫ | Delete last digit (backspace) |
| ÷ | Division |
| × | Multiplication |
| − | Subtraction |
| + | Addition |
| = | Calculate result |
| . | Decimal point |
| 0-9 | Number input |

## UI Design

- **Dark theme** with modern button styling
- **Orange** operator buttons (+, −, ×, ÷)
- **Blue** equals button (=)
- **Gray** number and function buttons
- **Rounded corners** on all UI elements
- **Hover highlighting** on all buttons
- **Press effects** for tactile feedback

## License

This project is provided as-is for educational purposes.
